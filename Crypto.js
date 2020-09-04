var SignedXml = require('xml-crypto').SignedXml	  
      , fs = require('fs')
 
//var xml = "<library>" +
//                "<book>" +
//                  "<name>Harry Potter</name>" +
//                "</book>" +
//              "</library>"


var select = require('xml-crypto').xpath
, dom = require('xmldom').DOMParser
, SignedXml = require('xml-crypto').SignedXml
, FileKeyInfo = require('xml-crypto').FileKeyInfo  
, fs = require('fs')

var xml = fs.readFileSync("pacs008.xml").toString()
//var doc = new dom().parseFromString(xml)   

var sig = new SignedXml()
sig.digestAlgorithm  = "http://www.w3.org/2001/04/xmlenc#sha256"
sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
sig.addReference("//*[local-name(.)='Document']", ['http://www.w3.org/TR/2001/REC-xml-c14n-20010315'], ['http://www.w3.org/2001/04/xmlenc#sha256'])    
sig.signingKey = fs.readFileSync("piv.pem")
sig.computeSignature(xml)
fs.writeFileSync("signed4.xml", sig.getSignedXml())
