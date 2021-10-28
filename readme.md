# transcert

transcert is a coverage-directed technique to much more effectively test real-world certificate validation code.  Our core insight is to (1) leverage easily accessible Internet certificates as seed certificates, and (2) use code coverage, particularly a coverage transfer graph, to direct certificate mutation towards generating a set of diverse certificates. 

## How to start

1. Generate a  self-signed certificate as the root CA certificate, and collect some certificates from the Internet as seeds. See details in the `./certificate` folder.
2. Generate a set of diverse certificates for differentially testing SSL/TLS implementations. See details in the `./code` folder.
3. `./data` folder contains sample test cases for 11 reasons summarized in the paper, and the rules extracted from RFC 5280.

