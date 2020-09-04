var select = require('xml-crypto').xpath
, dom = require('xmldom').DOMParser
, SignedXml = require('xml-crypto').SignedXml
, FileKeyInfo = require('xml-crypto').FileKeyInfo  
, fs = require('fs')

var xml = fs.readFileSync("signed4.xml").toString()
var doc = new dom().parseFromString(xml)    

var signature = select(doc, "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0]
var sig = new SignedXml()
sig.keyInfoProvider = new FileKeyInfo("pub.pem")
sig.loadSignature(signature)
var res = sig.checkSignature(xml)
console.log(res)
if (!res) console.log(sig.validationErrors)