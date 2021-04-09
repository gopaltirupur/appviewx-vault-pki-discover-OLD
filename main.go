//This Utility is to discover the certificates from the vault and upload to appviewx
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"
	"vault_util/aesencdec"
	"vault_util/appviewx"
	"vault_util/common"
	"vault_util/config"
	"vault_util/security"
	"vault_util/vault"

	"sync"

	"vault_util/ldb"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
)

var configFileNameFlag string
var vaultCertificateField string
var logLevel string
var logOutput string

const (
	concurrentNumber = 10
)

func main() {

	var discoveryCmd = getDiscoveryCommand()
	var listCommand = getListcommand()
	var resetCommand = getResetLocalCacheCommand()
	var install = getInstallCommand()

	var rootCmd = &cobra.Command{Use: "appviewx_vault_util"}
	rootCmd.AddCommand(discoveryCmd)
	rootCmd.AddCommand(listCommand)
	rootCmd.AddCommand(resetCommand)
	rootCmd.AddCommand(install)

	rootCmd.PersistentFlags().StringVarP(&logLevel, "log", "l", "info", "fatal error warn info debug trace - levels of logging  ")
	rootCmd.PersistentFlags().StringVarP(&logOutput, "log_output", "o", "", " 'file'  to divert output to predefined log file ")
	rootCmd.PersistentFlags().StringVarP(&configFileNameFlag, "config_file", "c", "./"+common.CONFIG_FILE_NAME, `Config file name with path  ( default "./`+common.CONFIG_FILE_NAME+`")
	
	Example : 
	{
		"appviewx_is_https": true,
		"appviewx_host": "<appviewx_host_name>",
		"appviewx_port": <appviewx_api_port>,
		"appviewx_username": "admin",		
		"vault_is_https": false,
		"vault_host": "<vault_host_name>",
		"vault_api_port": <vault_api_port>,
		"installation_path":"/tmp/test",
		"pki_engines":[
			{
				"name":"pki-1",
				"list_path":"certs",
				"get_path":"cert"
			},
			{
				"name":"appviewx-pki",
				"list_path":"certs",
				"get_path":"certs",
				"request_query":{
					"config":"appviewx_138"
				}
			}
		],
		"auto_discover_pki_engines":true,
		"vault_token": "s.tw7K2mSU3fgYMki8MOPDQDH0"
	}
	
`)

	discoveryCmd.Flags().StringVarP(&vaultCertificateField, "vault_certificate_field", "f", "certificate", `field name of certificate in get certificate resonse from vault`)
	install.Flags().StringVarP(&vaultCertificateField, "vault_certificate_field", "f", "certificate", `field name of certificate in get certificate resonse from vault - 
will be used during installation`)
	rootCmd.Execute()
}

func getDiscoveryCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "discover Certificate From the Vault and upload to AppViewX ( Uploaded Certificate details will be cached to skip in future )",
		Short: "Discover Certificate From the Vault and upload to AppViewX ( Uploaded Certificate details will be cached to skip in future )",
		Long:  "Discover the certificates from the configured vault and upload to AppViewX ( Uploaded Certificate details will be cached to skip in future )",
		Run:   carryoutDiscovery,
	}
}

func getListcommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list_from_vault lists the certificates in the vault",
		Short: "Lists the certificates in the vault based on the path given in " + common.CONFIG_FILE_NAME,
		Long:  "Lists the certificates in the vault based on the path given in " + common.CONFIG_FILE_NAME,
		Run:   displayList,
	}
}

func getResetLocalCacheCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "reset_local_cache resets the local upload details cache, After reset all certificates from vault will be uploaded to AppViewX",
		Short: "Resets the local upload details cache, After reset all certificates from vault will be uploaded to AppViewX",
		Long:  "Resets the local upload details cache, After reset all certificates from vault will be uploaded to AppViewX",
		Run:   resetLocalCache,
	}
}

func getInstallCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "install installs the utility",
		Short: "Install the utility",
		Long:  "Install the utility",
		Run:   install,
	}
}

func setLogLevel() (err error) {
	if logOutput == "file" {
		logFile := filepath.Join(common.GetHome(config.GetInstallationPath(configFileNameFlag)), common.INSTALLATION_DIRECTORY_NAME, common.LOG_FILE_NAME)
		f, errInner := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		log.SetOutput(f)

		if errInner != nil {
			log.Error("Error in opening the Log File : ", err)
			return errInner
		}
	}

	switch logLevel {
	case "fatal":
		log.SetLevel(log.FatalLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "trace":
		log.SetLevel(log.TraceLevel)
	}
	return
}

func install(cmd *cobra.Command, args []string) {
	ldb.StartDB(config.GetInstallationPath(configFileNameFlag))

	err := setLogLevel()
	if err != nil {
		return
	}

	log.Info("Starting install")
	installationPath := filepath.Join(common.GetHome(config.GetInstallationPath(configFileNameFlag)), common.INSTALLATION_DIRECTORY_NAME)

	log.Info("Installation path ", installationPath)

	err = os.MkdirAll(installationPath, 0777)
	if err != nil {
		log.Error("Error in creating the installation directory : ", err)
		return
	}
	currentWorkingDirectory, err := os.Getwd()
	if err != nil {
		log.Error("Error in creating the current working directory : ", err)
		return
	}
	binaryPath := filepath.Join(currentWorkingDirectory, common.INSTALLATION_DIRECTORY_NAME)
	copyFileToInstallationDirectory(binaryPath, installationPath, common.INSTALLATION_DIRECTORY_NAME)

	// configFile := filepath.Join(currentWorkingDirectory, common.CONFIG_FILE_NAME)
	copyFileToInstallationDirectory(configFileNameFlag, installationPath, common.CONFIG_FILE_NAME)

	// installationPathWithBinary := filepath.Join(installationPath, common.INSTALLATION_DIRECTORY_NAME)
	// subCommandsAndArguments := getSubCommandsAndArguments()
	// cron.PutEntryInCron(installCronString, installationPathWithBinary, subCommandsAndArguments)

	fmt.Println("Enter AppViewX Password : ")
	passwordContents, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Error("Error in Reading the password")
		return
	}

	encryptedPassword, err := aesencdec.Encrypt(security.SecurityString(), string(passwordContents))
	if err != nil {
		log.Error("Error in encrypting the password")
		return
	}

	err = ldb.PutByString("appviewx_password", encryptedPassword)
	if err != nil {
		log.Errorf("Error in putting the appviewx_password to ldb : %v", err)
		return
	}

	log.Info("Finished install")
}

func getSubCommandsAndArguments() (output string) {
	output += (" discover ")
	output += (" -f=" + vaultCertificateField + " ")
	output += (` -c="` + filepath.Join(common.GetHome(config.GetInstallationPath(configFileNameFlag)), common.INSTALLATION_DIRECTORY_NAME, common.CONFIG_FILE_NAME) + `" `)
	output += (" -l=" + logLevel)
	output += " -o=file "

	return
}

func copyFileToInstallationDirectory(fileNameWithPath, installationPath, targetFileName string) (err error) {

	log.Debug("Starting copyFileToInstallationDirectory")
	log.Debug("copyFileToInstallationDirectory : filePath : ", fileNameWithPath)
	log.Debug("copyFileToInstallationDirectory : installationPath : ", installationPath)

	binaryContent, err := ioutil.ReadFile(fileNameWithPath)
	if err != nil {
		log.Error("Error in Reading the Binary File from : ", fileNameWithPath, err)
		return
	}

	installationPathWithBinary := filepath.Join(installationPath, targetFileName)
	err = ioutil.WriteFile(installationPathWithBinary, binaryContent, 0777)
	if err != nil {
		log.Error("Error in Writing the Binary File at : ", installationPathWithBinary, err)
		return
	}
	log.Debug("Finished copyFileToInstallationDirectory")
	return
}

func resetLocalCache(cmd *cobra.Command, args []string) {
	ldb.StartDB(config.GetInstallationPath(configFileNameFlag))

	err := setLogLevel()
	if err != nil {
		return
	}

	log.Info("Starting resetLocalCache")

	leveldbFolderPath := filepath.Join(common.GetHome(config.GetInstallationPath(configFileNameFlag)), common.INSTALLATION_DIRECTORY_NAME, common.LEVEL_DB_FOLDER_NAME)
	log.Debug("FolderName for Remove : ", leveldbFolderPath)

	err = os.RemoveAll(leveldbFolderPath)

	log.Info("Finished resetLocalCache")
	if err != nil {
		log.Info("Error while removing the folder : ", leveldbFolderPath, err.Error())

		return
	}

}

func displayList(cmd *cobra.Command, args []string) {
	ldb.StartDB(config.GetInstallationPath(configFileNameFlag))

	err := setLogLevel()
	if err != nil {
		return
	}
	log.Debug("Starting displayList")

	_, hashiCorpVaultEnv, err := config.GetEnvironments(configFileNameFlag)
	if err != nil {
		log.Printf("Error in getting the environments : %+v\n", err)
		return
	}

	for _, currentVault := range hashiCorpVaultEnv.Vaults {
		setValueFromVault(hashiCorpVaultEnv, currentVault)

		log.Info("Processing Vault Hostname : %s ", currentVault.Host)
		if err = autoDiscoverPKIEngines(hashiCorpVaultEnv); err != nil {
			log.Errorf("Error in getting the PKIEnvines : %v", err)
			return
		}

		for _, currentPKIEngine := range hashiCorpVaultEnv.PKIEngines {
			log.Infof("\nProcessing Engine : %s", currentPKIEngine.Name)
			//set the currentPKIEngine
			setCurrentPKIEngine(currentPKIEngine, hashiCorpVaultEnv)

			listOfCertificates, err := hashiCorpVaultEnv.ListCertificates()

			for _, currentCertificate := range listOfCertificates {
				fmt.Println(currentCertificate)
			}

			if err != nil {
				log.Printf("Error in getting the certificate list : %+v ", err)
			}
		}
	}
	log.Debug("Finished displayList")
	return
}

func setValueFromVault(hashiCorpVaultEnv *vault.HashicorpVaultEnv, vault *vault.Vault) {
	hashiCorpVaultEnv.IsHTTPS = vault.IsHTTPS
	hashiCorpVaultEnv.Host = vault.Host
	hashiCorpVaultEnv.Port = vault.Port
	hashiCorpVaultEnv.PKIEngines = vault.PKIEngines
	hashiCorpVaultEnv.AutoDiscoverPKIEngines = vault.AutoDiscoverPKIEngines
	hashiCorpVaultEnv.VaultToken = vault.VaultToken
	hashiCorpVaultEnv.RequestPathListCertificates = vault.RequestPathListCertificates
	hashiCorpVaultEnv.RequestPathGetCertificates = vault.RequestPathGetCertificates
	hashiCorpVaultEnv.RequestQuery = vault.RequestQuery
}

func carryoutDiscovery(cmd *cobra.Command, args []string) {
	ldb.StartDB(config.GetInstallationPath(configFileNameFlag))

	err := setLogLevel()
	if err != nil {
		return
	}
	log.Debug("Starting carryoutDiscovery")

	appViewXEnv, hashiCorpVaultEnv, err := config.GetEnvironments(configFileNameFlag)
	if err != nil {
		log.Errorf("Error in getting the environments : %+v\n", err)
		return
	}

	for _, currentVault := range hashiCorpVaultEnv.Vaults {
		setValueFromVault(hashiCorpVaultEnv, currentVault)
		log.Info("Processing Vault Hostname : %s ", currentVault.Host)
		if err = autoDiscoverPKIEngines(hashiCorpVaultEnv); err != nil {
			log.Errorf("Error in getting the PKIEnvines : %v", err)
			appViewXEnv.RaiseAlert(err.Error(), true)
			continue
		}

		totalNumberOfUploads := 0
		for _, currentPKIEngine := range hashiCorpVaultEnv.PKIEngines {
			log.Infof("\nProcessing Engine : %s", currentPKIEngine.Name)
			//set the currentPKIEngine
			setCurrentPKIEngine(currentPKIEngine, hashiCorpVaultEnv)

			//Ensure the group exists before upload
			appViewXEnv.CreateGroup(currentPKIEngine.Name)

			//discover for the currentPKIEngine
			totalNos, uploadedNos := doCertificateDiscovery(appViewXEnv, hashiCorpVaultEnv)
			totalNumberOfUploads += uploadedNos
			appViewXEnv.RaiseAlert(fmt.Sprintf("Vault HostName : %s, PKI Engine : %s, Total No of Certificates : %d, Uploaded No. of Certificates : %d", currentVault.Host,
				currentPKIEngine.Name, totalNos, uploadedNos), false)
		}
		log.Printf("currentVault.Host : %s, Total Number of Certificates Uploaded : %d\n", currentVault.Host, totalNumberOfUploads)
	}

}

func setCurrentPKIEngine(pkiEngine *vault.PKIEngine, hashiCorpVaultEnv *vault.HashicorpVaultEnv) {
	hashiCorpVaultEnv.PKIEngineName = pkiEngine.Name
	hashiCorpVaultEnv.RequestPathListCertificates = fmt.Sprintf("%s/%s", pkiEngine.Name, pkiEngine.ListPath)
	hashiCorpVaultEnv.RequestPathGetCertificates = fmt.Sprintf("%s/%s", pkiEngine.Name, pkiEngine.GetPath)
	hashiCorpVaultEnv.RequestQuery = pkiEngine.RequestQuery
}

func autoDiscoverPKIEngines(vault *vault.HashicorpVaultEnv) error {
	if !vault.AutoDiscoverPKIEngines {
		return nil
	}
	return vault.DiscoverPKIEngines()
}

func doCertificateDiscovery(appViewXEnv *appviewx.AppViewXEnv, hashiCorpVaultEnv *vault.HashicorpVaultEnv) (int, int) {
	numberOfCurrentUpload := 0
	certificateList, err := hashiCorpVaultEnv.ListCertificates()
	if err != nil {
		log.Errorf("Error in getting the list of certificates : %+v\n", err)
		return 0, 0
	}

	err = appViewXEnv.Login()
	if err != nil {
		log.Errorf("Error in Logging in to AppViewX : %+v\n", err)
		return 0, 0
	}

	var wg sync.WaitGroup
	chan1 := make(chan int, concurrentNumber)

	for i, currentCertificateName := range certificateList {
		status, err := ldb.GetByString(currentCertificateName)
		if err != nil {
			log.Errorf("Error in getting the value from ldb for : %s", currentCertificateName)
			continue
		}
		if status != "" {
			log.Debugf("Skip - Upload Already Done : %s", currentCertificateName)
			continue
		}
		//TODO: - TO REMOVE
		log.Tracef("currentCertificateName : %s", currentCertificateName)
		receivedCertificate, err := hashiCorpVaultEnv.GetCertificate(currentCertificateName, vaultCertificateField)
		if err != nil {
			log.Errorf("Error in getting the certificate : "+currentCertificateName+" %+v\n", err)
			continue
		}
		chan1 <- 1
		wg.Add(1)

		log.Debugf("%d : Certificate Name : %s", i, currentCertificateName)
		log.Debugf(" Length = %d", len(receivedCertificate))
		if len(currentCertificateName) <= 0 {
			continue
		}
		numberOfCurrentUpload++
		go appViewXEnv.UploadCertificate(hashiCorpVaultEnv.PKIEngineName, currentCertificateName, receivedCertificate, chan1, &wg)
	}
	wg.Wait()
	log.Printf("Number of Certificates Uploaded : %d\n", numberOfCurrentUpload)
	log.Debug("Finished carryoutDiscovery\n")
	return len(certificateList), numberOfCurrentUpload

}

func display(input interface{}) {
	contents, err := json.Marshal(input)
	if err != nil {
		log.Error("Error in Marshalling : ", err)
		return
	}
	log.Debug("Contents : %s\n", string(contents))
}
