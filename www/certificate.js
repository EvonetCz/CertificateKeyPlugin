var exec = require('cordova/exec');

var certificate = {
   getData: function(fnSuccess, fnError, filename, password){
      exec(fnSuccess, fnError, "CertificateKey", "getData", [filename, password]);
   }, 
   listData: function(fnSuccess, fnError, ico){
      exec(fnSuccess, fnError, "CertificateKey", "listData", [ico]);
   }
};

module.exports = certificate;
