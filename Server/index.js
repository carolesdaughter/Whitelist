// TODO: Nothing :)

const HTTP = require("http")
const FS = require("fs");
const Crypto = require("crypto");
const ReadLine = require("readline");

const Interface = ReadLine.createInterface({
  input: process.stdin,
  output: process.stdout
});

const TrueInput = "true";
const FalseInput = "false";

let CurrentWhitelists = [];

const GenerateNumber = function() {
	return Math.floor(Math.random() * (48 - 16 + 1)) + 48;
}

const GenerateString = function(Input) {
	let Characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  	let String = "";

	for (let Index = 0; Index < Input.length; Index++) {
  		Characters = Characters.replace(Input.charAt(Index), "");
	}
  
	for (let Index = 0; Index < GenerateNumber(); Index++) {
    	String += Characters.charAt(Math.floor(Math.random() * Characters.length));
	}
	
  	return String;
};

const GenerateNewInput = function(Input) {
	let RandomString = GenerateString(Input)
	let InputArray = Input.split("")
	let RandomArray = RandomString.split("")

	for (let Index = 0; Index < InputArray.length; Index++) {
    	const Random = Math.floor(Math.random() * (RandomArray.length + 1));
    	RandomArray.splice(Random, 0, InputArray[Index]);
  	}

	return RandomArray.join("")
}

const Hash = function(Whitelist) {
	let SHASum = Crypto.createHash("sha256");
	
	SHASum.update(Whitelist);

	return SHASum.digest("hex");
};

const InsertWhitelist = function(Whitelist) {
	FS.appendFile("whitelist/whitelists.txt", `\n${Whitelist}`, (Error) => {
		if (Error) {
			console.log(Error);
		} else {
			console.log(`${Whitelist} successfully inserted!`);
		}
	})
};

HTTP.createServer(async(Request, Response) => {
	let RequestIP = (Request.headers['x-forwarded-for'] || Request.socket.remoteAddress);
	let RequestHWID = (Request.headers["syn-fingerprint"] || Request.headers["sw-fingerprint"] || Request.headers["krnl-fingerprint"] || "None");

	let HashedIP = Hash(RequestIP);
	let HashedHWID = Hash(RequestHWID);

	let Whitelisted = false;

	if (Request.method == "POST") {
		let Whitelist = (Request.headers["whitelist"] || "None");

		if (CurrentWhitelists.includes(Whitelist)) {
			let Index = CurrentWhitelists.indexOf(Whitelist);
			CurrentWhitelists.splice(Index, 1)
			Response.end("true");
		} else {
			Response.end("false");
		}

		return
	}
	
	FS.readFile("whitelist/whitelists.txt", function(Error, Data) {
		if (Error) {
			console.log(Error);
		} else {
			if (Data.includes(HashedHWID)) {
				let IsWhitelisted = GenerateNewInput(TrueInput);

				CurrentWhitelists.push(IsWhitelisted)
				
				Response.setHeader("is-whitelisted", IsWhitelisted);
				Response.setHeader("whitelist-method", "hwid");
				
				let HTML = FS.createReadStream("whitelist/isWhitelisted.html");
				
				Whitelisted = true;
				HTML.pipe(Response);

				return
			} else if (Data.includes(HashedIP)) {
				let IsWhitelisted = GenerateNewInput(TrueInput);
				
				CurrentWhitelists.push(IsWhitelisted)
				
				Response.setHeader("is-whitelisted", IsWhitelisted);
				Response.setHeader("whitelist-method", "ip");
				
				let HTML = FS.createReadStream("whitelist/isWhitelisted.html");
				
				Whitelisted = true;
				HTML.pipe(Response);

				return
			}
		}
	});

	await new Promise(Resolve => setTimeout(Resolve, 1000));

	if (Whitelisted == false) {
		let IsWhitelisted = GenerateNewInput(FalseInput);
		
		Response.setHeader("is-whitelisted", IsWhitelisted);
		Response.setHeader("whitelist-method", "none");
		
		let Index = FS.createReadStream("whitelist/notWhitelisted.html");

		Index.pipe(Response);
	}
}).listen(8080);

process.stdin.on("keypress", (Chunk, Key) => {
	if (Key && Key.name == "y" && Key.ctrl) {
		Interface.question("\nEnter new whitelist (IP / HWID): ", (Input) => {
			InsertWhitelist(Hash(Input));
		});
	}
});

console.log(
`- made by magnet -

< ------------------- >

- press "Ctrl + Y" simultaneously to insert someones whitelist (HWID or IP) -
`)
