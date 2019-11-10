(function (sandbox) {
function MyAnalysis () {
	const fs = require("fs");
	const fd = fs.openSync("/dev/urandom", 'r');
	const secret = new Buffer(0x10);
	fs.readSync(fd, secret, 0, 0x10);
	fs.closeSync(fd);

	function errExit(msg)
	{
		console.log(msg);
		process.exit(-1)
	}

	function AnnotatedValue(val, shadow)
	{
		this.val = val;
		this.shadow = shadow;
	}
	AnnotatedValue.prototype.toString = ()=>"AnnotatedValue";
	function actual(val)
	{
		return val instanceof AnnotatedValue ? val.val : val;
	}
	function shadow(val)
	{
		return val instanceof AnnotatedValue ? val.shadow : false;
	}

	this._return = function()
	{
		errExit("Return statement not allowed!");
	};

	this._with = function (iid, val)
	{
		const aval = actual(val);
		const sval = shadow(val);
		var ret = {}
		for (var k in aval)
		{
			ret[k] = new AnnotatedValue(actual(aval[k]),
				shadow(aval[k]) || sval);
		}
		return {result: ret};
	};

	this.binaryPre = function(iid, op, left, right)
	{
		return {op:op,left:left,right:right,skip:true};
	};

	this.binary = function(iid, op, left, right, result)
	{
		const aleft = actual(left);
		const aright = actual(right);
		switch (op)
		{
		case "+":
			result = aleft + aright;
			break;
		case "-":
			result = aleft - aright;
			break;
		case "*":
			result = aleft * aright;
			break;
		case "/":
			result = aleft / aright;
			break;
		case "%":
			result = aleft % aright;
			break;
		case "<<":
			result = aleft << aright;
			break;
		case ">>":
			result = aleft >> aright;
			break;
		case ">>>":
			result = aleft >>> aright;
			break;
		case "<":
			result = aleft < aright;
			break;
		case ">":
			result = aleft > aright;
			break;
		case "<=":
			result = aleft <= aright;
			break;
		case ">=":
			result = aleft >= aright;
			break;
		case "==":
			result = aleft == aright;
			break;
		case "!=":
			result = aleft != aright;
			break;
		case "===":
			result = aleft === aright;
			break;
		case "!==":
			result = aleft !== aright;
			break;
		case "&":
			result = aleft & aright;
			break;
		case "|":
			result = aleft | aright;
			break;
		case "^":
			result = aleft ^ aright;
			break;
		case "delete":
			result = delete aleft[aright];
			break;
		case "instanceof":
			result = aleft instanceof aright;
			break;
		case "in":
			result = aleft in aright;
			break;
		default:
			errExit(op + " at " + iid + " not found");
		}
		return {result: new AnnotatedValue(result,
			shadow(left) || shadow(right))};
	};

	this.conditional = function(iid, result)
	{
		if (shadow(result))
		{
			errExit("Implicit flow not allowed!");
		}
		return {result: actual(result)};
	}

	this.forinObject = function(iid, val)
	{
		const aval = actual(val);
		return {result: aval}
	}

	this.getFieldPre = function(iid, base, offset)
	{
		return {base:base, offset:offset, skip:true};
	};
	this.getField = function(iid, base, offset)
	{
		return {result: new AnnotatedValue(
			actual(actual(base)[actual(offset)]),
			shadow(base) || shadow(offset))}
	};

	this.invokeFunPre = function(iid, f, base, args, isConstructor, isMethod)
	{
		return {f:f, base:base, args:args, skip:true}
	};
	this.invokeFun = function(iid, f, base, args)
	{
		f = actual(f);
		if (f === "Source")
		{
			let ret = [];
			for (let i = 0; i < 0x10; i++)
			{
				ret.push(new AnnotatedValue(secret[i], true));
			}
			return {result: new AnnotatedValue(ret, true)};
		}
		else if (f === "Sink")
		{
			if (shadow(args[0]))
			{
				errExit("Value passed into sink cannot be tained");
			}
			const arr = actual(args[0])
			if (!(arr instanceof Array) || arr.length !== 0x10)
			{
				errExit("must use an array with length 16 as the key");
			}
			for (let i = 0; i < arr.length; i++)
			{
				if (shadow(arr[i]))
				{
					errExit("Value passed into sink cannot be tained");
				}
				if (actual(arr[i]) !== secret[i])
				{
					errExit("Wrong key!")
				}
			}
			console.log(String(fs.readFileSync("flag")));
		}
		// else if (f === "dp")
		// {// TODO: debug, to remove
		// 	console.log(args[0]);
		// }
		else
		{
			errExit("Function call other than source and sink is not allowed");
		}
	};

	this.literal = function(iid, val)
	{
		return {result: new AnnotatedValue(val, false)};
	};

	this.putFieldPre = function (iid, base, offset, val)
	{
		return {base:base, offset:offset, val:val, skip:true};
	};
	this.putField = function(iid, base, offset, val)
	{
		const aval = actual(val);
		const abase = actual(base);
		const aoff = actual(offset);
		abase[aoff] = aval;
		if (!(base instanceof AnnotatedValue))
		{
			errExit("Unreachable");
		}
		base.shadow = shadow(base) || shadow(offset) || shadow(val);
		return {result: val};
	};

	this.unaryPre = function (iid, op, left)
	{
		return {op:op, left:left, skip:true};
	};
	this.unary = function (iid, op, left, result)
	{
		var aleft = actual(left);
		switch (op)
		{
		case "+":
			result = +aleft;
			break;
		case "-":
			result = -aleft;
			break;
		case "~":
			result = ~aleft;
			break;
		case "!":
			result = !aleft;
			break;
		case "typeof":
			result = typeof aleft;
			break;
		case "void":
			result = void (aleft);
			break;
		default:
			errExit(op + " at " + iid + " not found");
			break;
		}
		return {result: new AnnotatedValue(result, shadow(left))};
	};
}
sandbox.analysis = new MyAnalysis();
})(J$);