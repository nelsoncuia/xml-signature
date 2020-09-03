var SignedXml = require('xml-crypto').SignedXml	  
      , fs = require('fs')
 
var xml = "<library>" +
                "<book>" +
                  "<name>Harry Potter</name>" +
                "</book>" +
              "</library>"
 

var sig = new SignedXml()
sig.digestAlgorithm  = "http://www.w3.org/2001/04/xmlenc#sha256"
sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
sig.addReference("//*[local-name(.)='name']", ['http://www.w3.org/TR/2001/REC-xml-c14n-20010315'], ['http://www.w3.org/2001/04/xmlenc#sha256'])    
sig.signingKey = fs.readFileSync("piv.pem")
sig.computeSignature(xml)
fs.writeFileSync("signed3.xml", sig.getSignedXml())
