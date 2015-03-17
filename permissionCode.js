var _ = require("lodash");

var PermissionCode = function(params){

}

PermissionCode.prototype.encodePermission = function(params, defaultRights){
	var self = this;
	defaultRights = defaultRights?defaultRights:[];
	if(_.isString(params))
	{
		if(this.isValid(params))
			return params;
		else
			return undefined;
	}
	else if(_.isNumber(params)){
		return params
	}
	else
	{
		var ownerRights = params.owner;
		var publicRights = params.public;
		var groupRights = params.group;
		var toProc = [params.owner,params.group,params.public];
		toProc = _.map(toProc,function(rights){
			if(_.isArray(rights) || _.isString(rights) || rights == undefined)
			{
				if(rights == undefined)
					rights = defaultRights;
				return self.convertToPermissionSegment(rights);
			}
			else 
			{
				console.error("Cannot construct permission code from "+params);
				return undefined;
			}
		})
		if(_.size(_.compact(toProc)) == 0)//no permissions even given
			return undefined
		var code = _.reduce(toProc, function(memo, v, k){
			return (memo << 4)|v;
		})
		return code;
	}
}
PermissionCode.prototype.isValid = function(string){
	//TODO: do checking on input @string
	return true;
}
PermissionCode.prototype.revokePermission = function(code,string){
	if(string == 'owner')
		return code & 119 // 0000 1111 1111
	if(string == 'group')
		return code & 3855 // 1111 0000 1111
	if(string == 'public')
		return (code >> 4) << 4 //zero last 4 bits
	return 0;
}
PermissionCode.prototype.fromString = function(string){
	var owner = parseInt(string[0])
	var group = parseInt(string[1])
	var publicA = parseInt(string[2])
	if(
		!_.contains([0,1,2,3,4,5,6,7],owner) || 
		!_.contains([0,1,2,3,4,5,6,7],group) || 
		!_.contains([0,1,2,3,4,5,6,7],publicA) 
	) 
		return undefined;
	return (owner << 8) | (group << 4) | (publicA << 0)
}
PermissionCode.prototype.decodePermissionToString = function(code){
	if(code == undefined) {console.error("cannot decode ",code); return undefined}
	var owner = (code & (7 << 8))>>8
	var group = (code & (7 << 4))>>4
	var publicA = (code & (7 << 0))>>0
	return ""+owner+""+group+""+publicA
}
PermissionCode.prototype.decodePermissionToObject = function(code){
	function numToObj(char){
		return {
			read : (char & 4) > 0,
			write : (char & 2) > 0,
			execute : (char & 1) > 0
		}
	}
	var result = {
		owner:numToObj((code >> 8) & 7),
		group:numToObj((code >> 4) & 7),
		public:numToObj((code >> 0) & 7)
	}
	return result;
}
PermissionCode.prototype.decompose = function(code){
	return [(code >> 8) & 7, (code >> 4) & 7, (code >> 0) & 7]
}
PermissionCode.prototype.convertToPermissionSegment = function(rights){
	if(!_.isArray(rights)){console.error("Cannot construct permission code from "+rights); return;}
	var segment = 0;
	//TODO: support string->code conversion
	var canRead = (_.intersection(rights,["read","find","r"])).length>0;
	var canWrite = (_.intersection(rights,["write","update","insert","edit","w"])).length>0;
	var canExecute = (_.intersection(rights,["execute","run","e"])).length>0;
	var canSomething = false;//TODO: potentially for a 'delete' permission, or whatever
	var result =  (canSomething?8:0) | (canRead?4:0) | (canWrite?2:0) | (canExecute?1:0)
	return result;
}
PermissionCode.prototype.test = function(){
	var self = this;
	console.log("///TESTING///")
	//encoding tests
	console.log("--encoding--");
	var test1 = self.encodePermission({
		owner : [],
		group : [],
		public : []
	})
	var test2 = self.encodePermission({
		owner : ["r","w","e"],
		group : [],
		public : []
	})
	var test3 = self.encodePermission({
		group : ["r","w","e"],
		member : [],
		public : []
	})
	var test4 = self.encodePermission({
		public : ["r","w","e"],
		group : [],
		member : []
	})
	var test5 = self.encodePermission({
		owner : ["r"],
		group : ["r"],
		public : ["r"]
	})
	var test6 = self.encodePermission({
		owner : ["r","w","e"],
		group : ["r","w"],
		public : ["r"]
	})
	var test7 = self.encodePermission({

	})
	var test8 = self.encodePermission({
		owner : ["r","w","e"]
	})
	var test9 = self.encodePermission({
		group : ["r","w","e"]
	})
	var test10 = self.encodePermission({
		public : ["r","w","e"]
	})
	var test11 = self.encodePermission({
		owner : ["r","w","e"],
		public : ["r","w","e"]
	})
	var test12 = self.encodePermission({
		group : ["r","w","e"],
		owner : ["r","w","e"]
	})
	var test13 = self.encodePermission({
		group : ["r","w","e"],
		public : ["r","w","e"]
	})
	console.log("Test 1 ",test1,": ",test1==0)
	console.log("Test 2 ",test2,": ",test2==(7<<8))
	console.log("Test 3 ",test3,": ",test3==(7<<4))
	console.log("Test 4 ",test4,": ",test4==(7<<0))
	console.log("Test 5 ",test5,": ",test5==(4<<8 | 4<<4 | 4<<0))
	console.log("Test 6 ",test6,": ",test6==(7<<8 | 6<<4 | 4<<0))
	console.log("Test 7 ",test7,": ",test7==(0<<8 | 0<<4 | 0<<0))
	console.log("Test 8 ",test8,": ",test8==(7<<8 | 0<<4 | 0<<0))
	console.log("Test 9 ",test9,": ",test9==(0<<8 | 7<<4 | 0<<0))
	console.log("Test 10 ",test10,": ",test10==(0<<8 | 0<<4 | 7<<0))
	console.log("Test 11 ",test11,": ",test11==(7<<8 | 0<<4 | 7<<0))
	console.log("Test 12 ",test12,": ",test12==(7<<8 | 7<<4 | 0<<0))
	console.log("Test 13 ",test13,": ",test13==(0<<8 | 7<<4 | 7<<0))
	//Decode to string tests
	console.log("--decoding to strings--")
	var dec1 = self.decodePermissionToString(test1);
	var dec2 = self.decodePermissionToString(test2);
	var dec3 = self.decodePermissionToString(test3);
	var dec4 = self.decodePermissionToString(test4);
	var dec5 = self.decodePermissionToString(test5);
	var dec6 = self.decodePermissionToString(test6);
	var dec7 = self.decodePermissionToString(test7);
	var dec8 = self.decodePermissionToString(test8);
	var dec9 = self.decodePermissionToString(test9);
	var dec10 = self.decodePermissionToString(test10);
	var dec11 = self.decodePermissionToString(test11);
	var dec12 = self.decodePermissionToString(test12);
	var dec13 = self.decodePermissionToString(test13);
	console.log("Test 14 ",dec1,": ",dec1=="000")
	console.log("Test 15 ",dec2,": ",dec2=="700")
	console.log("Test 16 ",dec3,": ",dec3=="070")
	console.log("Test 17 ",dec4,": ",dec4=="007")
	console.log("Test 18 ",dec5,": ",dec5=="444")
	console.log("Test 19 ",dec6,": ",dec6=="764")
	console.log("Test 20 ",dec7,": ",dec7=="000")
	console.log("Test 21 ",dec8,": ",dec8=="700")
	console.log("Test 22 ",dec9,": ",dec9=="070")
	console.log("Test 23 ",dec10,": ",dec10=="007")
	console.log("Test 24 ",dec11,": ",dec11=="707")
	console.log("Test 25 ",dec12,": ",dec12=="770")
	console.log("Test 26 ",dec13,": ",dec13=="077")
	//Decode to object tests
	console.log("--decoding to objects--")
	var deco1 = self.decodePermissionToObject(test1);
	var deco2 = self.decodePermissionToObject(test2);
	var deco3 = self.decodePermissionToObject(test3);
	var deco4 = self.decodePermissionToObject(test4);
	var deco5 = self.decodePermissionToObject(test5);
	var deco6 = self.decodePermissionToObject(test6);
	var deco7 = self.decodePermissionToObject(test7);
	var deco8 = self.decodePermissionToObject(test8);
	var deco9 = self.decodePermissionToObject(test9);
	var deco10 = self.decodePermissionToObject(test10);
	var deco11 = self.decodePermissionToObject(test11);
	var deco12 = self.decodePermissionToObject(test12);
	var deco13 = self.decodePermissionToObject(test13);
	console.log("Test 28 ",deco1,": ",_.isEqual(deco1,{owner:{read:false,write:false,execute:false},group:{read:false,write:false,execute:false},public:{read:false,write:false,execute:false}}))
	console.log("Test 29 ",deco2,": ",_.isEqual(deco2,{owner:{read:true,write:true,execute:true},group:{read:false,write:false,execute:false},public:{read:false,write:false,execute:false}}))
	console.log("Test 30 ",deco3,": ",_.isEqual(deco3,{owner:{read:false,write:false,execute:false},group:{read:true,write:true,execute:true},public:{read:false,write:false,execute:false}}))
	console.log("Test 31 ",deco4,": ",_.isEqual(deco4,{owner:{read:false,write:false,execute:false},group:{read:false,write:false,execute:false},public:{read:true,write:true,execute:true}}))
	console.log("Test 32 ",deco5,": ",_.isEqual(deco5,{owner:{read:true,write:false,execute:false},group:{read:true,write:false,execute:false},public:{read:true,write:false,execute:false}}))
	console.log("Test 33 ",deco6,": ",_.isEqual(deco6,{owner:{read:true,write:true,execute:true},group:{read:true,write:true,execute:false},public:{read:true,write:false,execute:false}}))
	console.log("Test 34 ",deco7,": ",_.isEqual(deco7,{owner:{read:false,write:false,execute:false},group:{read:false,write:false,execute:false},public:{read:false,write:false,execute:false}}))
	console.log("Test 35 ",deco8,": ",_.isEqual(deco8,{owner:{read:true,write:true,execute:true},group:{read:false,write:false,execute:false},public:{read:false,write:false,execute:false}}))
	console.log("Test 36 ",deco9,": ",_.isEqual(deco9,{owner:{read:false,write:false,execute:false},group:{read:true,write:true,execute:true},public:{read:false,write:false,execute:false}}))
	console.log("Test 37 ",deco10,": ",_.isEqual(deco10,{owner:{read:false,write:false,execute:false},group:{read:false,write:false,execute:false},public:{read:true,write:true,execute:true}}))
	console.log("Test 38 ",deco11,": ",_.isEqual(deco11,{owner:{read:true,write:true,execute:true},group:{read:false,write:false,execute:false},public:{read:true,write:true,execute:true}}))
	console.log("Test 39 ",deco12,": ",_.isEqual(deco12,{owner:{read:true,write:true,execute:true},group:{read:true,write:true,execute:true},public:{read:false,write:false,execute:false}}))
	console.log("Test 40 ",deco13,": ",_.isEqual(deco13,{owner:{read:false,write:false,execute:false},group:{read:true,write:true,execute:true},public:{read:true,write:true,execute:true}}))

}
//Debug
//var pc = new PermissionCode();
//pc.test()

module['exports'] = PermissionCode