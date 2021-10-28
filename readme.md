# transcert

transcert is a coverage-directed technique to much more effectively test real-world certificate validation code.  Our core insight is to (1) leverage easily accessible Internet certificates as seed certificates, and (2) use code coverage, particularly a coverage transfer graph, to direct certificate mutation towards generating a set of diverse certificates. 

## How to start

1. Generate a  self-signed certificate as the root CA certificate, and collect some certificates from the Internet as seeds. See details in the `./certificate` folder.
2. Generate a set of diverse certificates for differentially testing SSL/TLS implementations. See details in the `./code` folder.
3. `./data` folder contains sample test cases for 11 reasons summarized in the paper, and the rules extracted from RFC 5280.

## The examples of shortcomings stated in Section 5.5

**All rules below are extracted from RFC 5280 and displayed in `./data/RFC rules.xlsx`, which can be easily found with the indexes.**

**The discrepancies triggered by transcert can be found in `Section 6` with the indexes.**
1. **CG1**: The length of all certificate chains constructed by RFCcert is 2. Rules requiring longer certificate chain or self signed certificates cannot be tested.
   
   Example: 
   
   a. **(Rule 44)** *"The DN MUST be unique for each subject entity certified by the one CA as defined by the issuer field."* Requires certificate chain with >= 3 length.
   
   b. **(CC3)** *"Validators differently process self-issued certificates."* Requires certificate chain with = 1 length.
2. **CG2**: RFCcert constructs each certificate for a single rule, which is insufficient for testing complex situations involving multiple rules.
   
   Example: 
   
   a. **(Rule 19)** *"The issuer field MUST contain a non-empty distinguished name (DN)."* RFCcert directly changes the issuer of a certificate in the certificate chain to empty without triggering a discrepancy; transcert can construct a complex scenario for testing this rule through mutation, that is, when a certificate issuer in the certificate chain is set to be empty, the subject of the previous certificate is also set to be empty, which triggers the discrepancy **(CC2)**.
   
   b. **(CC2)** *"Name chaining may or may not be performed between empty names."*
3. **CG3**: For a rule that may have multiple violations, \textsf{RFC\-cert} only tests some of them (usually one).

   Example:
   
   a. **(Rule 17)** *"Non-conforming CAs may issue certificates with serial numbers hat are negative or zero. Certificate users SHOULD be prepared to gracefully handle such certificates."* The serial number of the certificate to be tested can be 0, negative or more than 20 octets, but RFCcert only tests serial number with more than 20 otects. transcert have tested certificates with 0 serial number.
   
   b. **(Rule 168)** *"The pathLenConstraint field is meaningful only if the cA boolean is asserted and the key usage extension, if present, asserts the keyCertSign bit (Section 4.2.1.3)."* There are many ways to violate this rule. RFCcert violates by constructing BasicConstraints in the form of (CA: false & pathLen), and transact violates by constructing BasicConstraints in the form of (CA: true, & pathLen) plus KeyUsage without Keycertsign bit.
4. **CG4**: RFCcert relies on manual certificate construction, so that some certificates may violate unexpected rules other than the target ones, which may lead to useless or even erroneous test results.

   Example:
   
   a. **(Rule 109)** *"To promote interoperability, this profile RECOMMENDS that policy information terms consist of only an OID."* The certificate generated by RFCcert contains two identical policy OIDs, which not only violates the current rule, but also violates **Rule 106** -- *"A certificate policy OID MUST NOT appear more than once in a certificate policies extension."*
5. **RE1**: Some certificates that can trigger discrepancies cannot be constructed according to any of the rules in RFC 5280, because these discrepancies are caused by the wrong implementation of SSL/TLS or misunderstanding of the rules by the SSL/TLS developer.

   Example:
   
   a. **(CRL5)** *"The revocation date of a revoked certificate is in the future."* This certificate generated by transcert does not violate any rules in RFC 5280, but triggers a validation difference.
6. **RE2**: The classification employed by RFCcert is not accurate, and some producer rules which are ignored can also be used for testing SSL/TLS implementations.

   Example:
   
   a. Most rules involving the critical field of extensions are considered producers by RFCcert and therefore test case settings are ignored.
   
   b. **(CP3)** *"Validators differently recognize critical extensions."
   
   c. **(CRL2)** *"Non-critical extensions are marked as critical."*
7. **RE3**: \textsf{RFC\-cert} may neglect important information related to the target rule which exists in other sentences rather than the target one.

   Example:
   
   a. **(Rule 17)** *"Non-conforming CAs may issue certificates with serial numbers hat are negative or zero. Certificate users SHOULD be prepared to gracefully handle such certificates."* In fact, the rules extracted by RFCcert do not contain the former sentence, so that RFCcert ignore the possibility of 0 or nagative serial numbers.
8. **DT1**: Restricted by the certificate editing tool PyOpenSSL, a few certificate fields cannot be freely edited.

   Example:
   
   a. **(Rule 3)** *"This field MUST contain the same algorithm identifier as the signature field in the sequence tbsCertificate"* transcert cannot generate a certificate to violate this rule because of the PyOpenSSL's restriction.
10. **DT2**: \textsf{trans\-cert} relies on seed certificates and cannot generate some fields that do not exist in seeds.

   Example:
   
   a. **(Rule 169)** *"Where it appears, the pathLenConstraint field MUST be greater than or equal to zero."* transcert cannot generate a certificate with negative pathLenConstraint, because the seeds do not contain this situation.
