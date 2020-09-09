const { S_IFBLK } = require('constants')

var SignedXml = require('xml-crypto').SignedXml, fs = require('fs')

var rs = require('jsrsasign');
var x509 = new rs.X509();


var select = require('xml-crypto').xpath
    , dom = require('xmldom').DOMParser
    , SignedXml = require('xml-crypto').SignedXml
    , FileKeyInfo = require('xml-crypto').FileKeyInfo
    , fs = require('fs')


//Function to generate KeyInfo (It is a modified version of the function inside xml-crypto library)
SignedXml.prototype.getKeyInfo = function(prefix) {
    var res = ""
    var currentPrefix
    
    currentPrefix = prefix || ''
    currentPrefix = currentPrefix ? currentPrefix + ':' : currentPrefix
    
    if (this.keyInfoProvider) {
        x509.readCertPEM(certString);
        res += "<" + currentPrefix + "KeyInfo id=\"" + x509.getExtAuthorityKeyIdentifier().kid.hex + "\">"
        //res += "<" + currentPrefix + "KeyInfo>"
        res += this.keyInfoProvider.getKeyInfo(this.signingKey, prefix)
        res += "</" + currentPrefix + "KeyInfo>"
    }
    return res
}


function MyKeyInfo(keyFile) {
    this.getKeyInfo = function (key, prefix) {
        prefix = prefix || ''
        prefix = prefix ? prefix + ':' : prefix
        x509.readCertPEM(certString);
        //O id de KeyInfo deve ser x509.getExtAuthorityKeyIdentifier().kid.hex
        return "<" + prefix + "X509Data>"+
                   "<X509IssuerSerial>" +
                       "<X509IssuerName>" + x509.getIssuerString() +"</X509IssuerName>" +
                       "<X509SerialNumber>" + x509.getSerialNumberHex() + "</X509SerialNumber>" +
                   "</X509IssuerSerial>" +
               "</" + prefix + "X509Data>"
    }
    this.getKey = function (keyInfo) {
        //you can use the keyInfo parameter to extract the key in any way you want      
        return fs.readFileSync(keyFile)
    }
}

var xml = fs.readFileSync("pacs008.xml").toString()
var certString = fs.readFileSync("cert.pem").toString()
//var doc = new dom().parseFromString(xml)   

var sig = new SignedXml()
sig.digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256"
sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
sig.signingKey = fs.readFileSync("key.pem")
sig.keyInfoProvider = new MyKeyInfo("cert.pem")
sig.addReference("//*[local-name(.)='Document']", ['http://www.w3.org/TR/2001/REC-xml-c14n-20010315'], ['http://www.w3.org/2001/04/xmlenc#sha256'])
//sig.addReference("//*[local-name(.)='AppHdr']", ['http://www.w3.org/TR/2001/REC-xml-c14n-20010315'], ['http://www.w3.org/2001/04/xmlenc#sha256'])
//sig.addReference("//*[local-name(.)='KeyInfo']", ['http://www.w3.org/TR/2001/REC-xml-c14n-20010315'], ['http://www.w3.org/2001/04/xmlenc#sha256'])     
sig.computeSignature(xml, {
    location: {
        reference: "//*[local-name(.)='Sgntr']",
        action: "append"
    }
})
fs.writeFileSync("signed8.xml", sig.getSignedXml())


//aki = x509.getSerialNumberHex();
//console.log("issuer STRING", x509.getIssuerString()) //É o CN daqui que eu devo usar na tag <X509IssuerName>
//console.log(rs.X509.getPublicKeyInfoPropOfCertPEM(certString))
//console.log("serial number", aki)
//console.log("keyInfo", sig.keyInfo)





