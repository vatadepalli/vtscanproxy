const https = require('https')
const querystring = require('querystring');

module.exports.scan = (event, context, callback) => {
  console.log(event);
  
  const url = event.queryStringParameters.url
  const apiKey = event.queryStringParameters.apiKey
  
  const options = {
    hostname: 'virustotal.com',
    port: 443,
    path: '/vtapi/v2/url/scan',
    method: 'POST',
    headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': querystring.stringify({
            'url' : url,
            'apikey': apiKey
        }).length
        }
  };

  req = https.request(options, (res) => {
    res.on('data', (d) => {
      console.log(d);
      callback(null, {
        statusCode: 200,
        body: JSON.stringify(JSON.parse(d), null, 2),
      })
    });
  })
  
  req.on('error', (e) => {
    callback(Error(e))
  })
  
  req.write(querystring.stringify({
    'url' : url,
    'apikey': apiKey
  }))
  
  req.end();
}

module.exports.result = (event, context, callback) => {
  const url = event.queryStringParameters.url
  const apiKey = event.queryStringParameters.apiKey

  let VTReportUrl = "https://www.virustotal.com/vtapi/v2/url/report?"
  
  https.get(VTReportUrl + "apikey=" + apiKey + "&resource=" + url, (resp) => {
    let data = '';

    // A chunk of data has been recieved.
    resp.on('data', (chunk) => {
        data += chunk;
    });

    // The whole response has been received. Print out the result.
    resp.on('end', () => {
        callback(null, {
          statusCode: 200,
          body: JSON.stringify(JSON.parse(data), null, 2)
        })
    });

    }).on("error", (err) => {
        callback(Error(err))
    });
}