[comment]: # "Auto-generated SOAR connector documentation"
# Talos Intelligence

Publisher: Splunk Community  
Connector Version: 1.0.0  
Product Vendor: Cisco  
Product Name: Talos Cloud Intelligence  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.2.1.305  

This app provides investigative actions for Talos Intelligence


Replace this text in the app's **readme.html** to contain more detailed information


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Talos Cloud Intelligence asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** |  required  | string | Base URL provided by Talos
**certificate** |  optional  | password | Certificate contents to authenticate with Talos
**key** |  optional  | password | Private key to authenticate with Talos

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[ip reputation](#action-ip-reputation) - Queries IP info  
[domain reputation](#action-domain-reputation) - Queries domain info  
[url reputation](#action-url-reputation) - Queries URL info  
[domain enrichment](#action-domain-enrichment) - Offers additional context on why a domain recieved an untrusted verdict  
[url enrichment](#action-url-enrichment) - Offers additional context on why an url recieved an untrusted verdict  
[ip enrichment](#action-ip-enrichment) - Offers additional context on why an ip recieved an untrusted verdict  
[domain prevalence](#action-domain-prevalence) - Provides prevelance data for organizational domains lor fully qualified domain names  
[ip prevalence](#action-ip-prevalence) - Provides prevelance data for organizational ips lor fully qualified ip names  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'ip reputation'
Queries IP info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ips` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip | string |  `ip`  |  
action_result.status | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data.\*.Observable | string |  |  
action_result.data.\*.Threat_Level | string |  |  
action_result.data.\*.Threat_Categories | string |  |  
action_result.data.\*.AUP | string |  |  
action_result.summary.message | string |  |   IP successfully queried   

## action: 'domain reputation'
Queries domain info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain`  `url` 
**ips** |  optional  | Corresponding IPs to the domain. A domain may have a different reputation based on the IP it resolves to. Passing an IP can improve the accuracy of the response | string |  `ips` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.domain | string |  `domain`  `url`  |  
action_result.parameter.ips | string |  `ips`  |  
action_result.status | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data.\*.Observable | string |  |  
action_result.data.\*.Threat_Level | string |  |  
action_result.data.\*.Threat_Categories | string |  |  
action_result.data.\*.AUP | string |  |  
action_result.summary.message | string |  |   Domain successfully queried   

## action: 'url reputation'
Queries URL info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to query | string |  `url` 
**ips** |  optional  | Corresponding IPs to the url. A domain may have a different reputation based on the IP it resolves to. Passing an IP can improve the accuracy of the response | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.url | string |  `url`  |  
action_result.parameter.ips | string |  `ips`  |  
action_result.status | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data.\*.Observable | string |  |  
action_result.data.\*.Threat_Level | string |  |  
action_result.data.\*.Threat_Categories | string |  |  
action_result.data.\*.AUP | string |  |  
action_result.summary.message | string |  |   URL successfully queried   

## action: 'domain enrichment'
Offers additional context on why a domain recieved an untrusted verdict

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain`  `url` 
**response_type** |  optional  | Response type of domain enrichment | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.domain | string |  `domain`  `url`  |  
action_result.status | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data.\*.name | string |  |  
action_result.data.\*.category | string |  |  
action_result.data.\*.description | string |  |  
action_result.summary.message | string |  |   Enrichment results for domain retrieved   

## action: 'url enrichment'
Offers additional context on why an url recieved an untrusted verdict

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to query | string |  `domain`  `url` 
**response_type** |  optional  | Response type of domain enrichment | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.url | string |  `domain`  `url`  |  
action_result.status | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data.\*.name | string |  |  
action_result.data.\*.category | string |  |  
action_result.data.\*.description | string |  |  
action_result.summary.message | string |  |   Enrichment results for url retrieved   

## action: 'ip enrichment'
Offers additional context on why an ip recieved an untrusted verdict

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip` 
**response_type** |  optional  | Response type of domain enrichment | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip | string |  `ip`  |  
action_result.status | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data.\*.name | string |  |  
action_result.data.\*.category | string |  |  
action_result.data.\*.description | string |  |  
action_result.summary.message | string |  |   Enrichment results for ip address retrieved   

## action: 'domain prevalence'
Provides prevelance data for organizational domains lor fully qualified domain names

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domains** |  required  | Comma seperated list of domains to query | string |  `domain`  `url` 
**first_seen** |  optional  | Timestamp in YYYY-MM-DD or YYYY-MM-DDThh:mm:ss formats representing the when first seen. If specified results only after seen on this date are returned | string | 
**last_seen** |  optional  | Timestamp in YYYY-MM-DD or YYYY-MM-DDThh:mm:ss formats representing the time last seen. If specified results only before this date are returned | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.domains | string |  `domain`  `url`  |  
action_result.parameter.first_seen | string |  |  
action_result.parameter.last_seen | string |  |  
action_result.status | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data.\*.count | numeric |  |  
action_result.data.\*.domain | string |  |  
action_result.data.\*.datasets.\*.dataset | string |  |  
action_result.data.\*.datasets.\*.count | string |  |  
action_result.data.\*.datasets.\*.first_seen | string |  |  
action_result.data.\*.datasets.\*.last_seen | string |  |  
action_result.data.\*.first_seen | string |  |  
action_result.data.\*.last_seen | string |  |  
action_result.summary.message | string |  |   Domain successfully queried   

## action: 'ip prevalence'
Provides prevelance data for organizational ips lor fully qualified ip names

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ips** |  required  | Comma seperated list of ips to query | string |  `ip` 
**first_seen** |  optional  | Timestamp in YYYY-MM-DD or YYYY-MM-DDThh:mm:ss formats representing the when first seen. If specified results only after seen on this date are returned | string | 
**last_seen** |  optional  | Timestamp in YYYY-MM-DD or YYYY-MM-DDThh:mm:ss formats representing the time last seen. If specified results only before this date are returned | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ips | string |  `ip`  |  
action_result.parameter.first_seen | string |  |  
action_result.parameter.last_seen | string |  |  
action_result.status | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data.\*.count | numeric |  |  
action_result.data.\*.domain | string |  |  
action_result.data.\*.datasets.\*.dataset | string |  |  
action_result.data.\*.datasets.\*.count | string |  |  
action_result.data.\*.datasets.\*.first_seen | string |  |  
action_result.data.\*.datasets.\*.last_seen | string |  |  
action_result.data.\*.first_seen | string |  |  
action_result.data.\*.last_seen | string |  |  
action_result.summary.message | string |  |   Domain successfully queried 