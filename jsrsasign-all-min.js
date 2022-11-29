/**
* Copyright (c) 2021, 2022, Oracle and/or its affiliates.  All rights reserved.
* This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl 
* or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
*/

// -------------------------------------------
// Oracle Cloud Infrastructure 
// Request Signature and OKE Kubernetes token
// v 2.0.0
// -------------------------------------------

// Checks if is an Oracle Cloud domain. Do nothing if not.
if (!pm.variables.replaceIn(pm.request.url.getHost()).includes("oraclecloud.com")) {return 0}

// Check OCI Credentials variables
if (!pm.environment.get("tenancy_ocid")) { throw new Error("Tenancy OCID (tenancy_ocid) Variable Not Set") }
if (!pm.environment.get("user_ocid")) { throw new Error("User OCID (user_ocid) Variable Not Set") }
if (!pm.environment.get("fingerprint")) { throw new Error("Key Fingerprint (fingerprint) Variable Not Set") }
if (!pm.environment.get("private_key")) { throw new Error("Private Key (private_key) Variable Not Set") }
if (!pm.environment.get("region")) { throw new Error("OCI Region (region) Variable Not Set") }

// jsrsasign (RSA-Sign JavaScript Library)
// https://github.com/kjur/jsrsasign LICENSE: MIT License
let navigator = {}
let window = {}
eval(pm.collectionVariables.get("jsrsasign"))

// Const Variables
const apiKeyId = `${pm.environment.get("tenancy_ocid")}/${pm.environment.get("user_ocid")}/${pm.environment.get("fingerprint")}`
const privateKey =  pm.environment.get("private_key")
const passphrase =  pm.environment.get("passphrase")
const rawClusterUrl = "https://containerengine.{{region}}.oraclecloud.com/cluster_request/{{cluster_ocid}}"

let authorizationString = (type) => {

    // Resolve host and paths
    let rawUrl = pm.request.url.getHost()
    let pathWithQuery = pm.request.url.getPathWithQuery()
    pathWithQuery.endsWith("?")?pathWithQuery=pathWithQuery.slice(0, -1):""
    if (type=="oke") {
        rawUrl = rawClusterUrl
        pathWithQuery = ""
    }

    // Get Host
    let URL = require('url')
    const urlHost = URL.parse(pm.variables.replaceIn(rawUrl))
    let host = urlHost.href
    let path = ""
    if(urlHost.hostname) {
        host = urlHost.hostname
        path = urlHost.path
    }
    (path.length==1&&path.match("[/]"))?path = "":""

    // Current date
    // Note: Maximum clock skew is 5 minutes
    const currentDate = new Date().toUTCString()
    //TODO: pm.collectionVariables.set("date",currentDate)
    pm.request.headers.upsert({key: "Date", value: currentDate})

    // Headers
    const hostHeader = `host: ${host}`
    const dateHeader = `date: ${currentDate}`
    const escapedTarget = encodeURI(path + pm.variables.replaceIn(pathWithQuery))
    const requestTargetHeader = `(request-target): ${request.method.toLowerCase()} ${escapedTarget}`

    // Siginig String
    let signingStringArray = [ 
                    requestTargetHeader,
                    dateHeader,
                    hostHeader
                ]

    let headersToSign = [
            "(request-target)",
            "date",
            "host"
        ]

    // Handles requests with body (POST, PUT and PATCH)
    const methodsThatRequireExtraHeaders = ["POST", "PUT", "PATCH"]
    const requestPath = pm.request.url.getPath()
    const objectStorageSpecial = (request.method.toUpperCase() == "PUT") && ((requestPath.startsWith("/n/")) && ((requestPath.includes("/o/") || requestPath.includes("/u/"))))?true:false
    if((methodsThatRequireExtraHeaders.indexOf(request.method.toUpperCase()) !== -1) && !objectStorageSpecial) {
        let body = pm.variables.replaceIn(pm.request.body.raw)
        body = (body?body:"")

        const contentLengthHeader = `content-length: ${Buffer.byteLength(body)}`
        const contentTypeHeader = "content-type: application/json"
        
        let bodyHash = new KJUR.crypto.MessageDigest({"alg": "sha256", "prov": "cryptojs"})
        bodyHash.updateString(body)
        const bHashVal = bodyHash.digest()
        const base64EncodedBodyHash = Buffer.from(bHashVal, 'hex').toString('base64')
        const contentSha256Header = `x-content-sha256: ${base64EncodedBodyHash}`
        //TODO: pm.collectionVariables.set("content_sha256",base64EncodedBodyHash)
        pm.request.headers.upsert({key: "x-content-sha256", value: base64EncodedBodyHash})
        
        signingStringArray = signingStringArray.concat([
            contentSha256Header,
            contentTypeHeader,
            contentLengthHeader
        ])

        headersToSign = headersToSign.concat([
            "x-content-sha256",
            "content-type",
            "content-length"
        ])
    }

    // Joins
    const headers = headersToSign.join(" ")
    const signingString = signingStringArray.join("\n")

    // Generates OCI Signature for Authorization
    let sig = new KJUR.crypto.Signature({"alg": "SHA256withRSA"})

    sig.init(privateKey,passphrase)
    sig.updateString(signingString)
    const hSigVal = sig.sign()
    const base64EncodedSignature = Buffer.from(hSigVal, 'hex').toString('base64')
    let response = `Signature version="1",keyId="${apiKeyId}",algorithm="rsa-sha256",headers="${headers}",signature="${base64EncodedSignature}"`

    if (type=="oke"){
        const tokenUrl = `${urlHost.href}?authorization=${encodeURIComponent(response)}&date=${encodeURIComponent(currentDate)}`
        response = CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(tokenUrl))
    }

    return response
}

//TODO: pm.collectionVariables.set("signature", authorizationString())
pm.request.headers.upsert({key: "Authorization", value: authorizationString()})
if (pm.environment.get("cluster_ocid")) { pm.collectionVariables.set("kube-oke-token", authorizationString("oke")) }
