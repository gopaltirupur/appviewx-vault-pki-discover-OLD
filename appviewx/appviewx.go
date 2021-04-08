//Package appviewx provides integration to the given appviewx environment
package appviewx

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
	"vault_util/aesencdec"
	"vault_util/common"
	"vault_util/ldb"
	"vault_util/security"

	log "github.com/sirupsen/logrus"

	"github.com/pkg/errors"
)

const (
	APPVIEWX_LOGIN_ACTION_ID              = "acctmgmt-perform-login"
	APPVIEWX_UPLOAD_CERTIFICATE_ACTION_ID = "cert-upload-server-certificate"
	APPVIEWX_CERT_GROUP_UPDATE            = "cert-group-update"
	APPVIEWX_RAISE_ALERT                  = "acctmgmt-receive-alert"
)

//AppViewXEnv to contain the appviewx environment details
type AppViewXEnv struct {
	IsHTTPS          bool   `json:"appviewx_is_https"`
	Host             string `json:"appviewx_host"`
	Port             int    `json:"appviewx_port"`
	UserName         string `json:"appviewx_username"`
	Password         string `json:"appviewx_password"`
	sessionID        string
	InstallationPath string `json:"installation_path"`
}

type CertGroupUpdateRequest struct {
	Payload CertGroupUpdateRequestPayload `json:"payload"`
}

type CertGroupUpdateRequestPayload struct {
	Name                 string               `json:"name"`
	Description          string               `json:"description"`
	AppID                string               `json:"appId"`
	ReportingTo          string               `json:"reportingTo"`
	PolicyName           string               `json:"policyName"`
	GroupBusinessInfo    GroupBusinessInfo    `json:"groupBusinessInfo"`
	GroupLevelCertConfig GroupLevelCertConfig `json:"groupLevelCertConfig"`
}

type GroupBusinessInfo struct {
	ContactName     string `json:"contactName"`
	PhoneNumber     string `json:"phoneNumber"`
	LobName         string `json:"lobName"`
	CostCenter      string `json:"costCenter"`
	EnvironmentName string `json:"environmentName"`
	InventoryNumber string `json:"inventoryNumber"`
	Email           string `json:"email"`
}

type GroupLevelCertConfig struct {
	AutoPushNeededAfterRenewReissue bool            `json:"autoPushNeededAfterRenewReissue"`
	AutoRenewConfig                 AutoRenewConfig `json:"autoRenewConfig"`
}

type AutoRenewConfig struct {
	RenewBefore                  int  `json:"renewBefore"`
	AutoRenewal                  bool `json:"autoRenewal"`
	ApprovalRequiredForAutoRenew bool `json:"approvalRequiredForAutoRenew"`
}

//CertificateUploadRequest to contain the certificate upload request details
type CertificateUploadRequest struct {
	Payload CertificateUploadRequestPayload `json:"payload"`
}

//CertificateUploadRequestPayload to contain the payload for certificate upload request
type CertificateUploadRequestPayload struct {
	FileContent         string `json:"fileContent"`
	FileName            string `json:"fileName"`
	CertificateCategory string `json:"certificateCategory"`
	GroupName           string `json:"groupName"`
}

type CertificateUploadResponse struct {
	Response      CertificateUploadResponseInternal `json:"response"`
	Message       string                            `json:"message"`
	AppStatusCode string                            `json:"appStatusCode"`
}

type CertificateUploadResponseInternal struct {
	UUID       string `json:"uuid"`
	Message    string `json:"message"`
	CommonName string `json:"commonName"`
	Category   string `json:"category"`
	ID         string `json:"id"`
}

type LoginRespopnse struct {
	Response      LoginRespopnseInternal `json:"response"`
	Message       string                 `json:"message"`
	AppStatusCode string                 `json:"appStatusCode"`
	Tags          interface{}            `json:"tags"`
	Headers       interface{}            `json:"headers"`
}

type LoginRespopnseInternal struct {
	Status                     string      `json:"status"`
	AppStatusCode              string      `json:"appStatusCode"`
	StatusDescription          interface{} `json:"statusDescription"`
	SessionID                  string      `json:"sessionId"`
	AvailableLoginAttemptCount string      `json:"availableLoginAttemptCount"`
}

type AppViewXAlert struct {
	Name       string `json:"name"`
	Message    string `json:"message"`
	Category   string `json:"category"`
	Severity   string `json:"severity"`
	Detail     string `json:"detail"`
	DeviceID   string `json:"deviceId"`
	DeviceName string `json:"deviceName"`
	SourceID   string `json:"sourceId"`
	Source     string `json:"source"`
	Time       string `json:"time"`
}

//Login - method to carry out the Login in the underlying appviewX environment
func (appviewxEnv *AppViewXEnv) Login() (err error) {
	log.Debug("Starting Login")
	url, err := appviewxEnv.getURLForGivenActionID(APPVIEWX_LOGIN_ACTION_ID)
	if err != nil {
		err = errors.Wrap(err, "Error in AppViewX Login")
		return err
	}
	payload := make(map[string]string)

	headers, err := appviewxEnv.getHeadersForLogin()
	if err != nil {
		return err
	}

	responseContents, err := common.MakePostCallAndReturnResponse(url, payload, headers, appviewxEnv.getQueryParam())
	if err != nil {
		err = errors.Wrap(err, "Error in AppViewX Login")
		log.Errorf("Error in Login : %v", err)
		return err
	}

	loginRespopnse := LoginRespopnse{}
	err = json.Unmarshal(responseContents, &loginRespopnse)
	if err != nil {
		log.Error("Error in Unmarshalling the response at AppViewX Login", err.Error())
		err = errors.Wrap(err, "Error in Unmarshalling the response at AppViewX Login")
		return
	}

	appviewxEnv.sessionID = loginRespopnse.Response.SessionID
	if len(appviewxEnv.sessionID) > 0 {
		log.Debug("Received AppViewX SessionID")
	}
	log.Debug("Finished Login")
	return
}

func getCertificateUploadRequest(pkiEngineName, certificate string) (certificateUploadRequest CertificateUploadRequest) {
	log.Debug("Starting getCertificateUploadRequest")
	certificateUploadRequest = CertificateUploadRequest{}
	certificateUploadRequest.Payload.FileContent = certificate
	certificateUploadRequest.Payload.FileName = "test.cer"
	certificateUploadRequest.Payload.CertificateCategory = "server"
	certificateUploadRequest.Payload.GroupName = pkiEngineName
	log.Debug("Finished getCertificateUploadRequest")
	return
}

func (appViewXEnv *AppViewXEnv) RaiseAlert(message string, isCritical bool) error {
	log.Debug("Starting RaiseAlert : %s", message)

	url, err := appViewXEnv.getURLForGivenActionID(APPVIEWX_RAISE_ALERT)
	if err != nil {
		log.Errorf("Error in RaiseAlert during the URL creation : %v", err)
		return fmt.Errorf("Error in RaiseAlert during the URL creation : %v", err)
	}

	if err = appViewXEnv.Login(); err != nil {
		log.Errorf("Error in RaiseAlert during the AppViewX Login : %v", err)
	}

	var severity string
	if isCritical {
		severity = "Critical"
	} else {
		severity = "Notification"
	}

	appviewxAlert := AppViewXAlert{
		Name:       "Certificate",
		Message:    message,
		Category:   "Certificate",
		Severity:   severity,
		Detail:     message,
		DeviceID:   "hashiCorpVaultDiscoverPlugin",
		DeviceName: "hashiCorpVaultDiscoverPlugin",
		SourceID:   "hashiCorpVault",
		Source:     "hashiCorpVault",
		Time:       fmt.Sprintf("%d", time.Now().UnixNano()/1000000),
	}

	responseContents, err := common.MakePostCallAndReturnResponse(url, map[string]interface{}{"payload": appviewxAlert},
		appViewXEnv.getHeadersWithSessionID(), appViewXEnv.getQueryParam())
	if err != nil {
		log.Errorf("Error in Raise Alert : %v", err)
		return err
	}
	log.Debugf("Raise Alert : responseContents : %s", string(responseContents))
	log.Debug("Finished Raise Alert")
	return nil
}

func (appViewXEnv *AppViewXEnv) CreateGroup(pkiEngineName string) error {
	log.Debug("Starting CreateGroup")

	certGroupUpdateRequest := CertGroupUpdateRequest{Payload: CertGroupUpdateRequestPayload{Name: pkiEngineName, ReportingTo: "Default", PolicyName: "Default"}}

	url, err := appViewXEnv.getURLForGivenActionID(APPVIEWX_CERT_GROUP_UPDATE)
	if err != nil {
		return fmt.Errorf("Error in Create Group during the URL creation : %v", err)
	}

	err = appViewXEnv.Login()
	if err != nil {
		return fmt.Errorf("Error in Logging in to AppViewX : %+v\n", err)
	}

	responseContents, err := common.MakePostCallAndReturnResponse(url, certGroupUpdateRequest, appViewXEnv.getHeadersWithSessionID(), appViewXEnv.getQueryParam())
	if err != nil {
		if !strings.Contains(err.Error(), "417 Expectation Failed") {
			log.Errorf("Error in Create Group at AppViewX : %v", err)
		}
		return fmt.Errorf("Error in Create Group at AppViewX : %v", err)
	}
	log.Debug("responseContents : ", string(responseContents))
	log.Debug("Finished CreateGroup")
	return nil
}

//UploadCertificate - method to carry out the certificate upload functionality in the underlying appviewx environment
func (appViewXEnv *AppViewXEnv) UploadCertificate(pkiEngineName, certificateName, certificate string, chanInput chan int, wg *sync.WaitGroup) (err error) {
	log.Debug("Starting UploadCertificate")

	certificate = base64.StdEncoding.EncodeToString([]byte(certificate))
	certificateUploadRequest := getCertificateUploadRequest(pkiEngineName, certificate)

	url, err := appViewXEnv.getURLForGivenActionID(APPVIEWX_UPLOAD_CERTIFICATE_ACTION_ID)
	if err != nil {
		updateChannelAndWaitGroup(chanInput, wg)
		err = errors.Wrap(err, "Error in Upload Certificate during the URL creation")
		return err
	}
	responseContents, err := common.MakePostCallAndReturnResponse(url, certificateUploadRequest, appViewXEnv.getHeadersWithSessionID(), appViewXEnv.getQueryParam())
	if err != nil {
		updateChannelAndWaitGroup(chanInput, wg)
		if strings.Contains(err.Error(), "Status:500") {
			log.Trace("Ignoring the UploadCertificate Error : ", err.Error())
			return
		}
		err = errors.Wrap(err, "Error in Upload Certificate")
		log.Errorf("Error in Upload Certificate : %v", err)
		return err
	}

	certificateUploadResponse := CertificateUploadResponse{}
	err = json.Unmarshal(responseContents, &certificateUploadResponse)
	if err != nil {
		updateChannelAndWaitGroup(chanInput, wg)
		log.Error("Error in Unmarshalling the response at Upload Certificate", err.Error())
		err = errors.Wrap(err, "Error in Unmarshalling the response at Upload Certificate")
		return
	}
	if strings.Contains(certificateUploadResponse.Message, "Unauthorized") {
		//Login Again and Retry Retry Upload One more time
		appViewXEnv.Login()
		_, err := common.MakePostCallAndReturnResponse(url, certificateUploadRequest, appViewXEnv.getDefaultHeaders(), appViewXEnv.getQueryParam())
		updateChannelAndWaitGroup(chanInput, wg)
		if err != nil {
			err = errors.Wrap(err, "Error in Upload Certificate")
			log.Errorf("Error in Upload Certificate : %v", err)
			return err
		}
	}
	ldb.PutByString(certificateName, "yes")
	updateChannelAndWaitGroup(chanInput, wg)
	log.Debug("Finished UploadCertificate")
	return
}

func updateChannelAndWaitGroup(c chan int, wg *sync.WaitGroup) {
	<-c
	wg.Done()
}

func (appviewxEnv AppViewXEnv) getURLForGivenActionID(actionID string) (output string, err error) {
	log.Debug("Starting getURLForGivenActionID")
	output, err = appviewxEnv.getCommonURL()
	if err != nil {
		return
	}
	output += (actionID)
	log.Debug("Finished getURLForGivenActionID")
	return
}

func (appviewxEnv AppViewXEnv) getCommonURL() (output string, err error) {
	if appviewxEnv.Host == "" || appviewxEnv.Port == 0 {
		log.Error("Config Validation Failed ")
		log.Error("appviewxEnv.Host : ", appviewxEnv.Host)
		log.Error("appviewxEnv.Port : ", appviewxEnv.Port)
		return "", errors.New(
			"Error in Config - Vault -" +
				" vault.Host : " + appviewxEnv.Host +
				" vault.Port : " + fmt.Sprintf("%d", appviewxEnv.Port))
	}

	if appviewxEnv.IsHTTPS {
		output += "https://"
	} else {
		output += "http://"
	}
	output += (appviewxEnv.Host + ":")
	output += (fmt.Sprintf("%d", appviewxEnv.Port) + "/avxapi/")
	return
}

func (appviewxEnv AppViewXEnv) getHeadersWithSessionID() (output map[string]string) {
	output = appviewxEnv.getDefaultHeaders()
	output["sessionId"] = appviewxEnv.sessionID
	return output
}

func (appviewxEnv AppViewXEnv) getDefaultHeaders() (output map[string]string) {
	output = make(map[string]string)
	output["Content-Type"] = "application/json"
	output["Accept"] = "application/json"
	return
}

func (appviewxEnv AppViewXEnv) getHeadersForLogin() (map[string]string, error) {
	log.Debug("Starting getHeadersForLogin")
	output := appviewxEnv.getDefaultHeaders()
	output["username"] = appviewxEnv.UserName

	password, err := getPassword(appviewxEnv.Password)
	if err != nil {
		return nil, err
	}

	output["password"] = password
	return output, nil
}

func (appviewxEnv AppViewXEnv) getQueryParam() (output map[string]string) {
	output = make(map[string]string)
	output["gwkey"] = "f000ca01"
	output["gwsource"] = "WEB"
	return
}

func getPassword(password string) (string, error) {
	log.Debug("Starting getPassword ", len(password))
	if password != "" {
		return password, nil
	}
	password, err := ldb.GetByString("appviewx_password")
	if err != nil {
		log.Error("Error in retrieving appviewx_password from ldb")
		return "", err
	}

	decryptedPassword, err := aesencdec.Decrypt(security.SecurityString(), password)
	if err != nil {
		log.Errorf("Error in decrypting the password : %v", err)
		return "", err
	}

	return decryptedPassword, nil
}
