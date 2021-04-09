# AppViewX Vault PKI Discover

The vault pki discover plugin enables the users to enhance visibility and governance on the high volumes certificates issued on [HashiCorp Vault](https://www.vaultproject.io/docs/secrets/pki)

The certificates which are issued by Vault are automatically discovered and managed by AppViewX Cert+ platform. Additionally the users are enabled with visibility of all the discovered certificates in a single pane of glass view along with life cycle management of the certificates and enforcement of policy to ensure compliance with enterprise security policy. 

The platform also enables the users to have a better control of the certificates with flexible monitoring and reporting features.

![AppViewX Vault PKI Discover](https://github.com/vigneshkathir/appviewx-vault-pki-discover/blob/main/images/AppViewX-Vault-PKI-Discover.jpeg)


## Integration Prerequisites

Before configuring the AppViewX Vault PKI discover plugin, the below prerequisites should be validated.

- [ ] Access to AppViewX
- [ ] HashiCorp Vault Instance with PKI engines
- [ ] Plugin installation on Linux distributions CentOS,Ubuntu,Mint
- [ ] Signup or try [AppViewX](https://www.appviewx.com/try-appviewx/)

> Note : Existing customers and for support reach us @ help@appviewx.com

# Vault PKI Discover plugin configuration

## Installation Steps

 - Download appviewx-vault-pki-discover from the github.com to the machine where the plugin to be installed.
	```bash
	git clone https://github.com/AppViewX/appviewx-vault-pki-discover.git
	```
- Change the working directory to **appviewx-vault-pki-discover**  and update the AppViewX Instance and Vault Instance host details in the config.json file.
	```bash
		cd <installdirectory>/appviewx-vault-pki-discover/
	```
 - Sample config file
	```
	{
	"appviewx_is_https": true,  
	"appviewx_host": "<AppViewX Host>",
	"appviewx_port": 5300,
	"appviewx_username": "<AppViewX Username>",
	"installation_path": "",  // Install path of the plugin
	"vaults": [{
			"vault_is_https": false, // set to true if vault running in https 
			"vault_host": "127.0.0.1", // Vault Host 1
			"vault_api_port": 5920, // Vault port
			"pki_engines": [{
					"name": "pki-1", // PKI engine  configured on Vault
					"list_path": "certs",
					"get_path": "cert"
				}],
			"auto_discover_pki_engines": true, // set to true for discovering all pki engines ; set to false only if the above configured engine has to be discovered
			"vault_token": "s.PB4WVVzYlPPxUPSf8u9NZyKI" // Vault user token with access to list and read pki engines.
		},
		{
			"vault_is_https": false, // set to true if vault running in https 
			"vault_host": "127.0.0.1",  // Vault Host 1
			"vault_api_port": 5920, // Vault port
			"pki_engines": [{
					"name": "pki-1", // PKI engine  configured on Vault
					"list_path": "certs",
					"get_path": "cert"
				}],
			"auto_discover_pki_engines": true, // set to true for discovering all pki engines ; set to false only if the above configured engine has to be discovered
			"vault_token": "s.PB4WVVzYlPPxUPSf8u9NZyKI"  // Vault user token with access to list and read pki engines.
		}
	]
	}
	```
> Note : The config in the sample provides the capability to discover ssl certificates from multiple vaults with the option to auto discover PKI engines on vault or either fallback to discover certificate from specified PKI engine. 

 - Access to vault can be restricted with privilege to list and read ssl certificates by configuring vault policy and associating the policy to a user token. The token should be updated in the config.json.
 - Execute the below step to install the plugin.
	```bash
	./appviewx_vault_util install -c ./config.json
	```
> Note : If the config.json is provided with an installation path the plugin will be installed on the specified path. Alternatively if the installation path is empty, the plugin will be installed in the **home**  directory.

## Plugin Usage

AppViewX vault discover plugin executable and the config file can be found in the installation path specified during the installation.

**Discover SSL Certificates** 
- To discover the ssl certificates from the PKI engine execute the below command.
	```bash
	</install_path_plugin/>/appviewx_vault_util discover  -c=config.json 
	```
**List SSL Certificates**

- To list the ssl certificates from the PKI engine execute the below command.
	```bash
	</install_path_plugin/>/appviewx_vault_util list_from_vault
	```
**Reset Local Cache**

- Reset local cache will remove certificates from the plugin cache which were discovered from the vault instance.
	```bash
	</install_path_plugin/>/appviewx_vault_util reset_local_cache
	```
>Note : The reset local cache when executed will delete the certificates in the cache and when the discover command is executed it will update the cache with all certificates from the vault instance and this will create duplicate certificates in AppViewX.

**Miscellaneous**

The plugin supports inbuilt help mode to display the list of functions support and the usage around it.
Execute the below command for help.
```bash
 </install_path_plugin/>/appviewx_vault_util -h
 ```
To run the appviewx vault discover plugin on a scheduled mode, the user can configure cron on the linux machine and configure the absolute path where the plugin is installed in the cron.
