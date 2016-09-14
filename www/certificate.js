var exec = require('cordova/exec');

var certificate = {
   getData: function(fnSuccess, fnError, filename, password){
      exec(fnSuccess, fnError, "CertificateKey", "execute", [filename, password]);
   }
};

module.exports = printer;
