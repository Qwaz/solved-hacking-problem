#!/usr/local/bin/node
'use strict';
var cgiHttpContext = require('cgi-node');

//cgiHttpContext.write("");

var config = require("config");

const wasm_launcher = "sendcc.js";

function convertIntPtr(charPtr){
    var convertedValue = "";
    for (let pointer = 0; pointer < 20; pointer++) {

        var tmp2 = Module.HEAPU32[charPtr / Uint32Array.BYTES_PER_ELEMENT  + pointer];

        if (tmp2 >= 0x20 && tmp2 < 0x7f){
            convertedValue += String.fromCharCode(tmp2) + "";
        } else {
            break;
        }
    }
    return convertedValue;
}

function processRequest(req, resp){
    let Module = require(wasm_launcher);
    global.Module = Module;
    Module['onRuntimeInitialized'] = onRuntimeInitialized;
    var transactionId = "";
    function successCB(ptrRespMessage, responseCode, ptrResponseTransId ) {

        var responseTransID = convertIntPtr(ptrResponseTransId);

        if (transactionId === responseTransID){
            resp.redirect(config.cc.build_authd_url(responseTransID));
        } else {
            resp.redirect("/purchase.html?message=Authorized id did not match sent id")
        }
        delete require.cache[require.resolve(wasm_launcher)];
        global.Module = null;

    }

    function failCB(ptrRespMessage, responseCode, responseTransId ) {

        var responseMessage = "";

        for (let pointer = 0; pointer < 1000; pointer++) {

            var tmp2 = Module.HEAPU32[ptrRespMessage/ Uint32Array.BYTES_PER_ELEMENT  + pointer];

            if (tmp2 >= 0x20 && tmp2 < 0x7f){
                responseMessage += String.fromCharCode(tmp2) + "";
            } else {
                break;
            }
        }
        var body = "\nresponse=" +responseCode+ "," + responseMessage + "\n";

        resp.redirect("/purchase.html?message=" + responseMessage + " please re-enter the information.");

        delete require.cache[require.resolve(wasm_launcher)];

        global.Module = null;

    }

    function onRuntimeInitialized() {
        // init inputs
        try {
            var amount = 5995;
            var terminalID = config.cc.terminalID;
            var merchantID = config.cc.merchantID;

            var c = new this.CCInfo(req, amount.toString(), terminalID, merchantID);

            c.successCallback = successCB;
            c.failCallback = failCB;

            transactionId = c.checkout(config.cc.host, config.cc.port);

            config.cc.add_cert(transactionId);

        } catch (e) {
            console.log(e);
            throw e;
        }

    }

}

processRequest(cgiHttpContext.request, cgiHttpContext.response);

//app.get('/cc', processRequest);

