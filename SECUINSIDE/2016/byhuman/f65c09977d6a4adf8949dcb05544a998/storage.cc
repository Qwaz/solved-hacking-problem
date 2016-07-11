#include "common.h"

Storage::Storage() {
	RANDOM;
	type = VAR_STORAGE;
	state = 0;
#if DEBUG_LOG
	std::cout << "Storage();" << std::endl;
#endif
}

Storage::~Storage() {
	RANDOM;
#if DEBUG_LOG
	std::cout << "~Storage(" << Storage::toString()->toCString() << ");" << std::endl;
#endif
}

bool Storage::Set(ItemPtr key, ItemPtr value) {
	RANDOM;
	if(key.get() == NULL) return false;
	if(value.get() == NULL) return false;

	// Key must be string type.
	if(key->type != VAR_STRING) return false;

	// Insert to the map.
	items.insert(std::make_pair(
		std::move(key), std::move(value)));
	return true;
}

Item* Storage::Get(ItemPtr key) {
	RANDOM;
	// Key must be string type. For real..
	if(key->type != VAR_STRING) return NULL;
	return items[std::move(key)].get();
}

String *Storage::toString() {
	RANDOM;
	std::string newString("");
	bool isFirst = true;
	newString += "{\n";
	for(auto const &i: items) {
		if(isFirst == false) newString += ",\n";
		newString += "\t";
		newString += '"';
		newString = newString + i.first->toString()->toCString()->c_str();
		newString += "\": ";
		newString += '"';
		newString = newString + i.second->toString()->toCString()->c_str();
		newString += '"';
		isFirst = false;
	}
	newString += '\n';
	newString += '}';
	return new String(newString);
}

Number *Storage::toNumber(int base) {
	RANDOM;
	return new Number(items.size());
}

Storage *Storage::toStorage() {
	RANDOM;
	Storage *result = new Storage();
	for(auto const &i: items) {
		bool invalid;
		invalid = false;
		String *new_key = i.first->toString();
		Item *new_value;
		switch(i.second->type) {
			case VAR_NUMBER: {
				new_value = i.second->toNumber();
				break;
			}
			case VAR_STRING: {
				new_value = i.second->toString();
				break;
			}
			case VAR_STORAGE: {
				new_value = i.second->toStorage();
				break;
			}
			default:
				new_value = NULL;
		}
		if(new_value == NULL) invalid = true;
		if(invalid == false) {
			ItemPtr new_key_ptr(new_key);
			ItemPtr new_value_ptr(new_value);
			result->Set(std::move(new_key_ptr), std::move(new_value_ptr));
		}
	}
	return result;
}