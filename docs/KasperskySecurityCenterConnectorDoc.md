## About the connector
Kaspersky Security Center makes it easy to manage and secure both physical and virtual endpoints from a single, unified management console.
<p>This document provides information about the Kaspersky Security Center Connector, which facilitates automated interactions, with a Kaspersky Security Center server using FortiSOAR&trade; playbooks. Add the Kaspersky Security Center Connector as a step in FortiSOAR&trade; playbooks and perform automated operations with Kaspersky Security Center.</p>

### Version information

Connector Version: 1.0.1


Authored By: Fortinet

Contributors: Islam Baker, Vincent

Certified: No
## Installing the connector
<p>From FortiSOAR&trade; 5.0.0 onwards, use the <strong>Connector Store</strong> to install the connector. For the detailed procedure to install a connector, click <a href="https://docs.fortinet.com/document/fortisoar/0.0.0/installing-a-connector/1/installing-a-connector" target="_top">here</a>.<br>You can also use the following <code>yum</code> command as a root user to install connectors from an SSH session:</p>
`yum install cyops-connector-kaspersky-security-center`

## Prerequisites to configuring the connector
- You must have the URL of Kaspersky Security Center server to which you will connect and perform automated operations and credentials to access that server.
- The FortiSOAR&trade; server should have outbound connectivity to port 443 on the Kaspersky Security Center server.

### Minimum Permissions Required
- N/A

## Configuring the connector
For the procedure to configure a connector, click [here](https://docs.fortinet.com/document/fortisoar/0.0.0/configuring-a-connector/1/configuring-a-connector)
### Configuration parameters
<p>In FortiSOAR&trade;, on the Connectors page, click the <strong>Kaspersky Security Center</strong> connector row (if you are in the <strong>Grid</strong> view on the Connectors page) and in the <strong>Configurations&nbsp;</strong> tab enter the required configuration details:&nbsp;</p>
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Server URL<br></td><td>URL of the Kaspersky Security Center server to which you will connect and perform automated operations.<br>
<tr><td>Username<br></td><td>Username to access the Kaspersky Security Center server to which you will connect and perform automated operations.<br>
<tr><td>Password<br></td><td>Password to access the Kaspersky Security Center server to which you will connect and perform automated operations.<br>
<tr><td>Verify SSL<br></td><td>Specifies whether the SSL certificate for the server is to be verified or not. <br/>By default, this option is set as True.<br></td></tr>
</tbody></table>

## Actions supported by the connector
The following automated operations can be included in playbooks and you can also use the annotations to access operations from FortiSOAR&trade; release 4.10.0 and onwards:
<table border=1><thead><tr><th>Function<br></th><th>Description<br></th><th>Annotation and Category<br></th></tr></thead><tbody><tr><td>Get Host Group Static Info<br></td><td>Retrieves a host group static Info from the Kaspersky Security Center.<br></td><td>get_hosts_group_static_info <br/>Investigation<br></td></tr>
<tr><td>Get All Groups Details<br></td><td>Retrieves a list of all groups from the Kaspersky Security Center.<br></td><td>get_groups <br/>Investigation<br></td></tr>
<tr><td>Get Host Details<br></td><td>Retrieves a host details from the Kaspersky Security Center.<br></td><td>get_host_details <br/>Investigation<br></td></tr>
<tr><td>Get Host List<br></td><td>Retrives a list of all hosts located in specific group from the Kaspersky Security Center.<br></td><td>get_listhost_group <br/>Investigation<br></td></tr>
<tr><td>Get Products Installed<br></td><td>Retrives a kaspersky product details installed at specific host from the Kaspersky Security Center.<br></td><td>get_product_installed <br/>Investigation<br></td></tr>
<tr><td>Delete Specific Group<br></td><td>Deletes an specific administrative group in the Kaspersky Security Center.<br></td><td>delete_group <br/>Investigation<br></td></tr>
<tr><td>Add Group<br></td><td>Create a new administration group in Kaspersky Security Center.<br></td><td>add_group <br/>Investigation<br></td></tr>
<tr><td>Get Software Installed on Specefic Host<br></td><td>Retrives a list of all product details installed from the Kaspersky Security Center.<br></td><td>get_software_installed <br/>Investigation<br></td></tr>
<tr><td>Get All Policies on Specific Group<br></td><td>Retrives a policies located in specified group from the Kaspersky Security Center.<br></td><td>list_policies_request <br/>Investigation<br></td></tr>
<tr><td>Get Specific Policy<br></td><td>Retrive a specific policy from the Kaspersky Security Center.<br></td><td>get_policy_request <br/>Investigation<br></td></tr>
<tr><td>Add Policy<br></td><td>Create New Policy and assigned to specific Group in Kaspersky Security Center.<br></td><td>add_policy_request <br/>Investigation<br></td></tr>
<tr><td>Move Host to Specific Group<br></td><td>Move Host from group to other group in Kaspersky Security Center.<br></td><td>move_hosts <br/>Investigation<br></td></tr>
</tbody></table>

### operation: Get Host Group Static Info
#### Input parameters
None.
#### Output

 The output contains a non-dictionary value.
### operation: Get All Groups Details
#### Input parameters
None.

#### Output

 The output contains a non-dictionary value.

### operation: Get Host Details
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Host ID<br></td><td>Specify the ID of the host based on which you want to retrieve host details from Kaspersky Security Center.<br>
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Get Host List
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Group ID<br></td><td>Specify the ID of the group based on which you want to retrieve a list of all host details from Kaspersky Security Center.<br>
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Get Products Installed
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Host ID<br></td><td>Specify the ID of the host based on which you want to retrieve product details from Kaspersky Security Center.<br>
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Delete Specific Group
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Group ID<br></td><td>Specify the ID of the group based on which you want to delete a specific group in Kaspersky Security Center.<br>
</td></tr><tr><td>Value<br></td><td>Specify the value  based on which you want to delete a specific group in Kaspersky Security Center.<br>
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Add Group
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Group Parent ID<br></td><td>Specify the ID of the parent group based on which you want to create a new group in Kaspersky Security Center.<br>
</td></tr><tr><td>Group Name<br></td><td>Specify the name of the group based on which you want to create a new group in Kaspersky Security Center.<br>
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Get Software Installed on Specefic Host
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Host ID<br></td><td>Specify the ID of the host based on which you want to retrieves a product details from the Kaspersky Security Center.<br>
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Get All Policies on Specific Group
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Group ID<br></td><td>Specify the ID of the group based on which you want to retrieves list of all policies from Kaspersky Security Center.<br>
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Get Specific Policy
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Policy ID<br></td><td>Specify the ID of the policy based on which you want to retrieve a specific policy from Kaspersky Security Center.<br>
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Add Policy
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>Group Id<br></td><td>Specify the ID of the group based on which you want to create a new policy in Kaspersky Security Center.<br>
</td></tr><tr><td>Policy Display Name<br></td><td>Specify the display name of the policy based on which you want to create a new policy in Kaspersky Security Center.<br>
</td></tr><tr><td>Policy Product Name<br></td><td>Specify the product name of the policy based on which you want to create a new policy in Kaspersky Security Center.<br>
</td></tr><tr><td>Policy Product Version<br></td><td>Specify the product version of the policy based on which you want to create a new policy in Kaspersky Security Center.<br>
</td></tr><tr><td>Policy GROUP ID<br></td><td>Specify the group ID of the policy based on which you want to create a new policy in Kaspersky Security Center.<br>
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Move Host to Specific Group
#### Input parameters
<table border=1><thead><tr><th>Parameter<br></th><th>Description<br></th></tr></thead><tbody><tr><td>New Group ID<br></td><td>Specify the group ID based on which you want to move host to specific group in Kaspersky Security Center.<br>
</td></tr><tr><td>Host Name<br></td><td>Specify the name of the host based on which you want to move host to specific group in Kaspersky Security Center.<br>
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.
 
## Included playbooks
The `Sample - kaspersky-security-center - 1.0.0` playbook collection comes bundled with the Kaspersky Security Center connector. These playbooks contain steps using which you can perform all supported actions. You can see bundled playbooks in the **Automation** > **Playbooks** section in FortiSOAR<sup>TM</sup> after importing the Kaspersky Security Center connector.

- Add Group
- Add Policy
- Delete Specific Group
- Get All Groups Details
- Get All Policies on Specific Group
- Get Host Details
- Get Host Group Static Info
- Get Host List
- Get Products Installed
- Get Software Installed on Specefic Host
- Get Specific Policy
- Move Host to Specific Group

**Note**: If you are planning to use any of the sample playbooks in your environment, ensure that you clone those playbooks and move them to a different collection, since the sample playbook collection gets deleted during connector upgrade and delete.
