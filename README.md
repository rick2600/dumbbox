# dumbbox
A skeleton to create sandbox challenges for learning purposes.

## How it works?
The function dumbbox_setup() setups the sandbox by creating 2 processes. The more privileged process (called broker) acts as a service manager to the less privileged process (called target). When target process wants to open a file it must call dumbbox_unpriv_open() function. 
