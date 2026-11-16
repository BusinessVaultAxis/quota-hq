// Wraps the Quota HQ app page with the server shim -> public/index.html
const fs=require("fs"),src=process.argv[2];
let app=fs.readFileSync(src,"utf8").replace(/<title>[^<]*<\/title>\s*/,"");
const shim=fs.readFileSync(__dirname+"/shim.js","utf8");
fs.writeFileSync(__dirname+"/public/index.html",`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>Quota HQ</title><link rel="icon" href="/logo.svg"><meta name="theme-color" content="#0F1210"><script>${shim}</script></head><body>
${app}
</body></html>`);
console.log("built public/index.html",fs.statSync(__dirname+"/public/index.html").size);
