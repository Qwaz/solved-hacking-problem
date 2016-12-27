#include "common.h"

namespace c {
	const char StrNull[] = "(null)";
	const char *typeString[] = {
		"Item",
		"Number",
		"String",
		"Storage"
	};
}

Item::Item() {
	type = VAR_ITEM;
#if DEBUG_LOG
	std::cout << "Item(" << std::hex << this << ");" << std::endl;
#endif
}

Item::~Item() {
#if DEBUG_LOG
	std::cout << "~" << c::typeString[type] << "(" << std::hex << this << ");" << std::endl;
#endif
	type = VAR_ITEM;
}

String *Item::toString() {
	String *result = new String(c::StrNull);
	return result;
}

Number *Item::toNumber(int base) {
	Number *result = new Number(0);
	return result;
}

Storage *Item::toStorage() {
	Storage *result = new Storage();
	return result;
}