#include "common.h"

enum Opcodes {
	OP_ADD = 0,
	OP_DEFINE,
	OP_JUMP,
	OP_SET,
	OP_EVAL,
	OP_IF,
	OP_RETURN,
	OP_CONVERT
};

std::vector<ItemPtr> refs;

Item *readNumber(char *&, char *);
Item *readStorage(char *&, char *);
Item *readString(char *&, char *);
Item *readItem(char *&, char *);

Item *readNumber(char *&current, char *end) {
	RANDOM;
	if(current <= end - 4) {
		int value = *reinterpret_cast<int *>(current);
		Item *result = static_cast<Item *>(new Number(value));
		current += 4;
		return result;
	} else {
		current = end;
		return NULL;
	}
}

Item *readStorage(char *&current, char *end) {
	RANDOM;
	ItemPtr length(readNumber(current, end));
	if(length.get() == NULL) return NULL;
	int length_ = length->toNumber()->Get();
	Storage *result_ptr(new Storage());
	if(result_ptr == NULL) return NULL;
	for(int i = 0; i < length_; i++) {
		Item *key = readItem(current, end);
		if(key == NULL) return NULL;
		if(key->type != VAR_STRING) return NULL;
		Item *value = readItem(current, end);
		if(value == NULL) return NULL;
		result_ptr->Set(ItemPtr(key), ItemPtr(value));
	}
	return result_ptr;
}

Item *REF(int id) {
	RANDOM;
	if(id < (int)refs.size() && id >= 0) {
		return refs[id].get();
	} else {
		return NULL;
	}
}

int RREF(Item *a) {
	RANDOM;
	int id = refs.size();
	refs.push_back(std::move(ItemPtr(a)));
	return id;
}

Item *readString(char *&current, char *end) {
	RANDOM;
	ItemPtr length(readNumber(current, end));
	Number *length_num_ = static_cast<Number *>(length.get());
	if(length_num_ == NULL) return NULL;
	if(length_num_->Get() > 0x10000) return NULL;
	current += length_num_->Get();
	if(current > end) {
		current = end;
		return NULL;
	} else
		return (new String((char *)current - length_num_->Get(), length_num_->Get()));
}

Item *readItem(char *&current, char *code_end) {
	RANDOM;
	if(current == code_end) return NULL;
	int type = *current++;
	Item *result;
	switch(type) {
		case VAR_STORAGE: {
			result = readStorage(current, code_end);
			break;
		}
		case VAR_NUMBER: {
			result = readNumber(current, code_end);
			break;
		}
		case VAR_STRING: {
			result = readString(current, code_end);
			break;
		}
		default:
			result = NULL;
	}
	return result;
}

Item *eval(const char *code, int length) {
	RANDOM;
	Item *result = new Item();
	char *code_end = (char *)code + length;
	char *current = (char *)code;
	int refId1, refId2, refId3;
	int newType;
	int convertBase;
	int c;
#define readByte(target) {if(current == code_end) return NULL; else target=*current++;}
	while(current < code_end) {
		readByte(c);

		switch(c) {
			case OP_ADD: {
				readByte(refId1);
				readByte(refId2);
				Number *ref1 = static_cast<Number*>(REF(refId1));
				Number *ref2 = static_cast<Number*>(REF(refId2));
				if(ref1 && ref2) {
					if(ref1->type != VAR_NUMBER || ref2->type != VAR_NUMBER) return NULL;
					ref1->Add(ref2);
					result = ref1;
				} else {
					result = NULL;
				}
				break;
			}
			case OP_DEFINE: {
				result = new Number(RREF(readItem(current, code_end)));
				break;
			}
			case OP_JUMP: {
				int addr = *reinterpret_cast<int *>(current);
				if(addr < 0) return NULL;
				if(addr > length) return NULL;
				current = (char *)code + addr;
				break;
			}
			case OP_SET: {
				readByte(refId1);
				Storage *ref1 = static_cast<Storage*>(REF(refId1));
				if(ref1 == NULL) return NULL;
				if(ref1->type != VAR_STORAGE) return NULL;
				readByte(refId2);
				Item *ref2 = REF(refId2);
				readByte(refId3);
				Item *ref3 = REF(refId3);
				ItemPtr ref2_ptr(ref2);
				ItemPtr ref3_ptr(ref3);
				ref1->Set(std::move(ref2_ptr), std::move(ref3_ptr));
				ref2_ptr.reset();
				ref3_ptr.reset();
				break;
			}
			case OP_EVAL: {
				readByte(refId1);
				String *ref1 = static_cast<String*>(REF(refId1));
				if(ref1 == NULL) return NULL;
				if(ref1->type != VAR_STRING) return NULL;
				std::string *code_str = ref1->toCString();
				result = eval(code_str->c_str(), code_str->size());
				break;
			}
			case OP_IF: {
				readByte(refId1);
				int addr = *reinterpret_cast<int *>(current);
				Number *ref1 = REF(refId1)->toNumber();
				if(ref1->Get() == 0) {
					if(addr < 0) return NULL;
					if(addr > length) return NULL;
					current = (char *)code + addr;
				} else {
					current += 4;
				}
			}
			case OP_RETURN: {
				readByte(refId1);
				result = REF(refId1);
				break;
			}
			case OP_CONVERT: {
				readByte(refId1);
				Item *ref = REF(refId1);
				readByte(newType);
				switch(newType) {
					case VAR_STRING:
						result = new Number(RREF(ref->toString()));
						break;
					case VAR_NUMBER:
						readByte(convertBase);
						convertBase += 1;
						result = new Number(RREF(ref->toNumber(convertBase)));
						break;
					case VAR_STORAGE:
						result = new Number(RREF(ref->toStorage()));
						break;
					default:
						result = NULL;
						break;
				}
				break;
			}
			default: {
				result = NULL;
			}
		}
	}
	return result;
#undef readByte
}