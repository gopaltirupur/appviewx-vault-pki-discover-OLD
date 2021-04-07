//Package vault provides the integration to the given vault environment
package vault

import (
	"encoding/json"
	"fmt"
	"strings"
	"vault_util/common"

	log "github.com/sirupsen/logrus"

	"github.com/pkg/errors"
)

//HashicorpVaultEnv to contain the HashicorpVault environment details
type HashicorpVaultEnv struct {
	IsHTTPS                     bool
	Host                        string
	Port                        int
	PKIEngineName               string
	RequestPathListCertificates string
	RequestPathGetCertificates  string
	RequestQuery                map[string]string
	PKIEngines                  []*PKIEngine
	Vaults                      []*Vault `json:"vaults"`
	AutoDiscoverPKIEngines      bool
	VaultToken                  string
}

type Vault struct {
	IsHTTPS                     bool         `json:"vault_is_https"`
	Host                        string       `json:"vault_host"`
	Port                        int          `json:"vault_api_port"`
	PKIEngines                  []*PKIEngine `json:"pki_engines"`
	AutoDiscoverPKIEngines      bool         `json:"auto_discover_pki_engines"`
	VaultToken                  string       `json:"vault_token"`
	RequestPathListCertificates string
	RequestPathGetCertificates  string
	RequestQuery                map[string]string
}

//PKIEngine to specify a PKI Engine path details
type PKIEngine struct {
	Name         string            `json:"name"`
	ListPath     string            `json:"list_path"`
	GetPath      string            `json:"get_path"`
	RequestQuery map[string]string `json:"request_query"`
}

//VaultResponse contains the common vault response details
type VaultResponse struct {
	RequestID     string      `json:"request_id"`
	LeaseID       string      `json:"request_id"`
	IsRenewable   interface{} `json:"renewable"`
	LeaseDuration int         `json:"lease_duration"`
	WrapInfo      interface{} `json:"wrap_info"`
	Warnings      interface{} `json:"warnings"`
	Auth          interface{} `json:"auth"`
}

//VaultCertListResponse contains the List response from the vault
type VaultCertListResponse struct {
	VaultResponse
	Data VaultCertListData `json:"data"`
}

//VaultCertListData to contain the list of keys in the data objects received as resonse from the vault for the list call
type VaultCertListData struct {
	Keys []string `json:"keys"`
}

//VaultGetCertificateResponse to contain the certificate resopnse details
type VaultGetCertificateResponse struct {
	VaultResponse
	Data VaultCertificateData `json:"data"`
}

type VaultCertificateData struct {
	Alternatives interface{} `json:"alternatives"`
	Certificate  string      `json:"certificate"`
	CommonName   string      `json:"common_name"`
	CSR          string      `json:"csr"`
	PrivateKey   string      `json:"private_key"`
	SerialNumber string      `json:"serial_number"`
	Status       bool        `json:"status"`
}

func (vault *HashicorpVaultEnv) SetToken(newToken string) {
	vault.VaultToken = newToken
}

func (vault *HashicorpVaultEnv) DiscoverPKIEngines() error {
	log.Debug("Starting DiscoverPKIEngines")
	url, err := vault.getURLForListPKIEngines()
	if err != nil {
		log.Errorf("Error in DiscoveyPKI engine getURLForListPKIEngines : %v", err)
		return fmt.Errorf("Error in DiscoveyPKI engine getURLForListPKIEngines : %v", err)
	}
	responseContents, err := common.MakeGetCallAndReturnResponse(url, vault.getHeaders(), nil)
	if err != nil {
		log.Errorf("Error in DiscoveryPKI engine MakeGetCallAndReturnResponse : %v", err)
		return fmt.Errorf("Error in DiscoveryPKI engine MakeGetCallAndReturnResponse : %v", err)
	}

	vaultPKIEnginesResponse := map[string]interface{}{}
	err = json.Unmarshal(responseContents, &vaultPKIEnginesResponse)
	if err != nil {
		log.Errorf("Error in Unmarshalling the response at vaultPKIEnginesResponse %s", err.Error())
		return fmt.Errorf("Error in Unmarshalling the response at vaultPKIEnginesResponse %s", err.Error())
	}

	if len(vault.PKIEngines) <= 0 {
		vault.PKIEngines = []*PKIEngine{}
	}

	for name, vaultPKIEngine := range vaultPKIEnginesResponse {
		engineMap, ok := vaultPKIEngine.(map[string]interface{})
		if !ok {
			continue
		}
		if engineType, ok := engineMap["type"]; ok && fmt.Sprintf("%s", engineType) == "pki" {
			pkiEngine := PKIEngine{}
			pkiEngine.Name = strings.Trim(name, "/")
			pkiEngine.ListPath = "certs"
			pkiEngine.GetPath = "cert"
			vault.PKIEngines = append(vault.PKIEngines, &pkiEngine)
		}
	}

	hashiCorpVaultEnvContents, err := json.Marshal(vault)
	if err != nil {
		log.Errorf("Error in Marshalling the vault : ", err)
	}
	log.Tracef("After autoDiscoverPKIEngines hashiCorpVaultEnv : %s", string(hashiCorpVaultEnvContents))

	return nil
}

//ListCertificates method to get the list of certificates available in the vault
func (vault HashicorpVaultEnv) ListCertificates() (output []string, err error) {
	log.Debug("Starting ListCertificates")
	url, err := vault.getURLForListCertificates()
	if err != nil {
		return nil, err
	}
	log.Tracef("url : %s", url)
	responseContents, err := common.MakeGetCallAndReturnResponse(url, vault.getHeaders(), vault.getQueryParamsForList())
	if err != nil {
		log.Errorf("Error in List Certificates : %v : %s", err, string(responseContents))
		err = errors.Wrap(err, "Error in List Certificates")
		return nil, err
	}

	vaultCertListResponse := VaultCertListResponse{}
	err = json.Unmarshal(responseContents, &vaultCertListResponse)
	if err != nil {
		log.Error("Error in Unmarshalling the response at List Certificates ", err.Error())
		return nil, errors.Wrap(err, "Error in Unmarshalling the response at List Certificates ")
	}
	log.Debug("List of Certificate Common Names : ")
	for _, commonName := range vaultCertListResponse.Data.Keys {
		output = append(output, commonName)
	}
	log.Info("Number of Certificates In Vault: ", len(output))
	log.Debug("Finished ListCertificates")
	return
}

//GetCertificate method to get the given certificate
func (vault HashicorpVaultEnv) GetCertificate(certificateName, vaultCertificateField string) (output string, err error) {
	log.Debug("Starting GetCertificate")
	url, err := vault.getURLForGetCertificate()
	if err != nil {
		return "", err
	}
	url += ("/" + certificateName)

	responseContents, err := common.MakeGetCallAndReturnResponse(url, vault.getHeaders(), vault.RequestQuery)
	if err != nil {
		err = errors.Wrap(err, "Error in Get Certificate")
		return "", err
	}

	vaultGetCertificateResponse := VaultGetCertificateResponse{}
	err = json.Unmarshal(responseContents, &vaultGetCertificateResponse)
	if err != nil {
		log.Println("Error in Unmarshalling the resopnse at the Get Certificate ", err.Error())
		return "", errors.Wrap(err, "Error in Unmarshalling the resopnse at the Get Certificate")
	}
	output = vaultGetCertificateResponse.Data.Certificate
	log.Debug("Finished GetCertificate")
	return
}

func (vault HashicorpVaultEnv) getURLForListPKIEngines() (output string, err error) {
	output, err = vault.getURL()
	if err != nil {
		return "", err
	}
	output += "/v1/sys/mounts"
	return
}

func (vault HashicorpVaultEnv) getURLForListCertificates() (output string, err error) {
	output, err = vault.getURL()
	if err != nil {
		return "", err
	}
	output += ("/v1/" + vault.RequestPathListCertificates)
	return
}

func (vault HashicorpVaultEnv) getURLForGetCertificate() (output string, err error) {
	output, err = vault.getURL()
	if err != nil {
		return "", err
	}
	output += ("/v1/" + vault.RequestPathGetCertificates)
	return
}

func (vault HashicorpVaultEnv) getURL() (output string, err error) {
	if vault.Host == "" || vault.Port == 0 {
		log.Println("Config Validation Failed ")
		log.Println("vault.Host : ", vault.Host)
		log.Println("vault.Port : ", vault.Port)
		return "", errors.New(
			"Error in Config - Vault -" +
				" vault.Host : " + vault.Host +
				" vault.Port : " + fmt.Sprintf("%d", vault.Port) +
				"vault.RequestPathListCertificates : " + vault.RequestPathListCertificates +
				"vault.RequestPathGetCertificates : " + vault.RequestPathGetCertificates)
	}

	if vault.IsHTTPS {
		output += "https://"
	} else {
		output += "http://"
	}
	output += (vault.Host + ":")
	output += fmt.Sprintf("%d", vault.Port)
	return
}

func (vault HashicorpVaultEnv) getQueryParamsForList() (output map[string]string) {
	output = make(map[string]string)
	for key, value := range vault.RequestQuery {
		output[key] = value
	}
	output["list"] = "true"
	return
}

func (vault HashicorpVaultEnv) getHeaders() (output map[string]string) {
	output = make(map[string]string)
	output["X-Vault-Token"] = vault.VaultToken
	return
}
