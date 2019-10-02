package e2e

import (
	"fmt"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"
		"strings"
	"os/exec"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/stretchr/testify/assert"
	//"github.com/openshift/windows-machine-config-operator/tools/windows-node-installer/pkg/cloudprovider"
)

// Object that stores the instance info (instance id and security group) value
type InstanceInfo struct {
	InstanceIDs      []string
	SecurityGroupIDs []string
}

func TestE2ECreatingAndDestroyingWindowsInstanceOnEC2(t *testing.T) {
	// Get kubeconfig, AWS credentials, and artifact dir from environment variable set by the OpenShift CI operator.
	kubeconfig := os.Getenv("KUBECONFIG")
	awscredentials := os.Getenv("AWS_SHARED_CREDENTIALS_FILE")
	artifactDir := os.Getenv("ARTIFACT_DIR")

	awsCloud, err := cloudprovider.CloudProviderFactory(kubeconfig, awscredentials, "default", artifactDir,
		"ami-06a4e829b8bbad61e", "m4.large", "libra")
	assert.NoError(t, err, "error creating clients")

	// The e2e test assumes Microsoft Windows Server 2019 Base image, m4.large instance type, and libra sshkey are
	// available.
	err = awsCloud.CreateWindowsVM()
	assert.NoError(t, err, "error creating Windows instance")

	instanceInfo := getInstanceInfo(t)
	instanceId := instanceInfo.InstanceIDs[0]
	sgId := instanceInfo.SecurityGroupIDs[0]

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-1")},
	)
	assert.NoErrorf(t, err, "Couldn't create new aws session: %s", err)
	svc := ec2.New(sess)

	testWinrmPort(t, instanceId, sgId, svc)
	testWinrmAnsible(t, instanceId, svc)

	err = awsCloud.DestroyWindowsVMs()
	assert.NoError(t, err, "error deleting instance")
}

// Helper function reading the windows-node-installer.json and retrieve the instance info for testing function
func getInstanceInfo(t *testing.T, artifactDir string) InstanceInfo {
	// jsonFile, err := os.Open("/home/leojia/winc-2/windows-machine-config-operator/windows-node-installer.json")
	nodeInfoPath := artifactDir + "/windows-node-installer.json"
	jsonFile, err := os.Open(nodeInfoPath)
	assert.NoErrorf(t, err, "error reading windows-node-installer.json: %s", err)
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	var instanceInfo InstanceInfo
	json.Unmarshal(byteValue, &instanceInfo)
	return instanceInfo
}

// This test check the security group of the instance and verify that the
// winrm port are in security group inbound rule so that the
// instance is able to listen to winrm request.
func testWinrmPort(t *testing.T, instanceId string, sgId string, svc *ec2.EC2) {
	// Testing winrm port
	input := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []*string{
			aws.String(sgId),
		},
	}
	SgResult, err := svc.DescribeSecurityGroups(input)
	assert.Nilf(t, err, "Couldn't retirve Security Group: %s", err)

	// Verify winrm port and protocol are in the inbound rule of the security group
	portOpenResult := false
	for _, rule := range SgResult.SecurityGroups[0].IpPermissions {
		if rule.FromPort != nil && *rule.FromPort == 5986 {
			portOpenResult = true
		}
	}
	assert.Truef(t, portOpenResult, "Port 5986 is not open, test failed.")
}

// This test verify the connection of Windows instance using Ansible ping
// module. If the module executed successfully, which means the Windows instance
// is ready for Ansible communication.
func testWinrmAnsible(t *testing.T, instanceId string, svc *ec2.EC2) {
	// Getting instance ip address
	result, err := svc.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: []*string{
			aws.String(instanceId),
		},
	})
	assert.NoErrorf(t, err, "Couldn't DescribeInstances: %s", err)
	ipAddress := *result.Reservations[0].Instances[0].PublicIpAddress

	// instanceId := "i-07c5a035c05898075"
	ipAddressArg := ipAddress + ","

	privateKey := os.Getenv("PRIVATE_KEY")
	privateKeyArg := "~/.ssh/" + privateKey
	// Retrieve instance password
   	outputByte, err := exec.Command("aws", "ec2", "get-password-data", "--instance-id", instanceId, "--priv-launch-key", privateKeyArg).Output()
	assert.NoErrorf(t, err, "Retrieve instance password failed: %s", err)
	output := fmt.Sprintf("%s", outputByte)
	outputNoSpace := strings.Fields(output)

	// pw := "?@Kf;78@vh?v-KaAK23.uMdL!!Glbjd%"
	pw := outputNoSpace[1]

	// Test winrm Ansible connection
	extraVars := fmt.Sprintf("ansible_user=Administrator ansible_password='%s' ansible_connection=winrm ansible_ssh_port=5986 ansible_winrm_server_cert_validation=ignore", pw)
	cmdAnsible := exec.Command("ansible", "all", "-i", ipAddressArg, "-e", extraVars, "-m", "win_ping", "-vvvvv")
	cmdAnsible.Stdout = os.Stdout
	cmdAnsible.Stderr = os.Stderr
	err = cmdAnsible.Run()
	assert.NoErrorf(t, err, "Winrm Ansible connection test failed: %s", err)
}