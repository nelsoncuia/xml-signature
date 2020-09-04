const { S_IFBLK } = require('constants')

var SignedXml = require('xml-crypto').SignedXml, fs = require('fs')

var rs = require('jsrsasign');
var x509 = new rs.X509();


var select = require('xml-crypto').xpath
    , dom = require('xmldom').DOMParser
    , SignedXml = require('xml-crypto').SignedXml
    , FileKeyInfo = require('xml-crypto').FileKeyInfo
    , fs = require('fs')

function MyKeyInfo(keyFile) {
    this.getKeyInfo = function (key, prefix) {
        console.log("textinho", key)
        console.log(prefix)
        prefix = prefix || ''
        prefix = prefix ? prefix + ':' : prefix
        x509.readCertPEM(certString);
        return "<" + prefix + "X509Data id=\""+ x509.getExtAuthorityKeyIdentifier().kid.hex +"\"></" + prefix + "X509Data>"
    }
    this.getKey = function (keyInfo) {
        console.log("serve serve")
        console.log(keyInfo)
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
sig.addReference("//*[local-name(.)='AppHdr']", ['http://www.w3.org/TR/2001/REC-xml-c14n-20010315'], ['http://www.w3.org/2001/04/xmlenc#sha256'])
//sig.addReference("//*[local-name(.)='KeyInfo']", ['http://www.w3.org/TR/2001/REC-xml-c14n-20010315'], ['http://www.w3.org/2001/04/xmlenc#sha256'])     
sig.computeSignature(xml, {
    location: {
        reference: "//*[local-name(.)='Sgntr']",
        action: "append"
    }
})
fs.writeFileSync("signed4.xml", sig.getSignedXml())


aki = x509.getSerialNumberHex();
console.log(x509.getIssuer())
console.log(x509.getIssuerHex())
console.log(x509.getIssuerString())
console.log(rs.X509.getPublicKeyInfoPropOfCertPEM(certString))
console.log(aki)
console.log(sig.keyInfo)





