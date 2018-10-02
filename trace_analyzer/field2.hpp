#include <vector>

using namespace std;

#define NONE 	0
#define INTEGER 1
#define STRING 	2
#define CONS 	3

#define REG		0
#define MEM 	1
#define IMM		2

#define BIG 0
#define LITTLE 1

#define SIO 	0 // signed integer overflow
#define UIO		1 // unsigned integer overflow
#define SIU 	2 // signed integer underflow
#define UIU		3 // unsigned integer underflow

class Instruction;
class Field;
class Operand;
class InstructionCount;
class CheckCheksum;
class FieldInstruction;
class FieldValue;
class OperandField;

class Instruction{
private:
	string insDis, ins, type, strOffsets, insAddress;
	int endian, id, address;
	vector<Operand*> operands;
	vector<string> offsets;

public:
	Instruction();
	Instruction(string line);
	Instruction(int id, string line);

	~Instruction();

	string getInsDis() const {return this->insDis;}
	string getIns() const {return this->ins;}
	string getInsAddress() const {return this->insAddress;}

	int getEndian() const {return this->endian;}
	int getId() const {return this->id;}
	int getAddress() const {return this->address;}

	string getEndianStr() const {
		switch (this->endian){
		case BIG:
			return string("Big Endian");
		case LITTLE: 
			return string("Little Endian");
		default:

			break;
		}
	}

	vector<string> getOffsets() const {return this->offsets;}
	vector<Operand*> getOperands() const {return this->operands;}

	bool isStringCompare(int size);
	bool isCompare(int size);

	void addOperand(Operand* operand){this->operands.push_back(operand);}

	void proccessOffset();
	void makeField(string offset, int ind);
	void makeField();

	void printOperands();

	bool operator==(const Instruction& ins) const;
};

class Field{
private:
	int start, end, size, type, endian; // little endian = 1
	vector<FieldInstruction*> instructions;
	vector<string> markers;
	vector<string> constraints;
	vector<string> interests;
	vector<string> strings;
	vector<InstructionCount*> insCount;
	vector<FieldValue*> values;

	string orignalValue;

public:
	Field();
	Field(int start, int end, int size);
	Field(string strOffset);
	Field(OperandField* operandField);
	~Field();

	int getStart() const {return this->start;}
	int getSize() const {return this->size;}
		
	string getOrignalValue() const {return this->orignalValue;}

	vector<string> getMarkers() const {return this->markers;}
	vector<string> getStrings() const {return this->strings;}
	vector<string> getInerests() const {return this->interests;}
	
	vector<FieldInstruction*> getInstructions() const {return this->instructions;}

	int getType() const { return this->type;}
	int getEndian() const {return this->endian;}

	FieldValue* getFieldValue(string value);
	vector<FieldValue*> getFieldValues() const {return this->values;}

	string getTypeStr() const {
		switch (this->type){
			case NONE:
				return string("NONE");
			case INTEGER:
				return string("INTEGER");
			case STRING:
				return string("STRING");
			case CONS:
				return string("CONS");
			default:
				return string("NONE");
		}
	}

	void setStart(int start) {this->start = start;}
	void setSize(int size) {this->size = size;}
	void setType(int type) {this->type = type;}
	void setOriginalValue(string value){this->orignalValue = value;}

	void addInstruction(Instruction* ins, int index);
	void addMarker(string marker){this->markers.push_back(marker);}
	void addConstraint(string constraint){this->constraints.push_back(constraint);}
	void addInterest(string interest){this->interests.push_back(interest);}
	void addString(string str){this->strings.push_back(str);}
	void addValue(FieldValue* value);

	//bool isInstructionExist(Instruction* ins);
	bool isFieldValueExist(FieldValue* fv);
	bool isMarkerExist(string marker);
	bool isConstraintExist(string constraint);
	bool isInterestExist(string interest);
	
	bool isStringExist(string str);

	bool operator==(const Field& field) const { 
		//cout << "compare: " << this->start << " " << field.getStart() << endl;
		return (this->start == field.getStart()) && (this->size && field.getSize());
	}

	void print();
};


class InstructionCount{
private:
	string ins;
	int count;

public:
	InstructionCount();
	~InstructionCount();

	void setIns(string ins) {this->ins = ins;};
	void setCount(int count) {this->count = count;};

	void incCount() {this->count++;};

	int getCount() const {return this->count;}
	string getIns() const {return this->ins;}

};

class Operand{
private:
	int index, size, type;
	vector<OperandField*> operandFields;
	bool isTaint;
	string value;

public:
	Operand();
	Operand(int index, string operand);
	Operand(int index, string operand, string strOffset);

	~Operand();

	void setIndex(int index) {this->index = index;}
	void setValue(string value) {this->value = value;}
	void setSize(int size) {this->size = size;}

	int getIndex() const {return this->index;}
	int getSize() const {return this->size;}

	string getValue() const {return this->value;}
	string getValue(int size) const {return this->value.substr(0, size*2);}
	//string getTaintValue(int size) const {
	//	if(this->taintOffset + size <= this->size)
	//		return this->value.substr(this->taintOffset, size*2);
	//	else
	//		return this->value.substr(this->taintOffset, (this->size-taintOffset)*2);
	//}

	unsigned long long getValueInt(int size) const {
		string stringValue = this->value.substr(0, size*2);

		unsigned long long intValue = stoull(stringValue , NULL, 16);
		reverse((char*)&intValue, ((char*)&intValue)+size);
		return intValue;
	}

	vector<OperandField*> getFields() const { return this->operandFields; }
	int getFieldOffset(int start, int size);
};

class OperandField{
private:
	int start, end, size, offset, type, endian;

public:
	OperandField();
	OperandField(int start, int end, int size, int offset, int endian);

	~OperandField();

	int getStart() const {return this->start;}
	int getEnd() const {return this->end;}
	int getSize() const {return this->size;}
	int getOffset() const {return this->offset;}
	int getEndian() const {return this->endian;}
};

class CheckCheksum{
private:
	string insDis;
	int insAddr;
	vector<Instruction*> instructions;
	vector<string> offsets;

public:
	CheckCheksum(string insDis, int insAddr);
	~CheckCheksum();

	string getInsDis() const {return this->insDis;}
	int getInsAddr() const {return this->insAddr;}

	vector<string> getOffsets() const {return this->offsets;}
	vector<Instruction*> getInstructions() const {return this->instructions;}

	void addOffsets(string offsets){this->offsets.push_back(offsets);}
	void addInstruction(Instruction* instruction){this->instructions.push_back(instruction);}
	bool isChecksum();
};

class FieldInstruction{
private:
	Instruction* instruction;
	int index;

public:
	FieldInstruction(Instruction* ins, int index){
		this->instruction = ins;
		this->index = index;
	}
	~FieldInstruction();

	Instruction* getInstruction() const {return this->instruction;}
	int getIndex() const {return this->index;}

	void setInstruction(Instruction* ins){this->instruction = ins;}
	void setIndex(int index){this->index = index;}
};

class FieldValue{
private:
	string value;
	FieldValue* prev;
	Instruction* instruction;
	int index;

public:
	FieldValue(Instruction* instruction, int index, string value, FieldValue* prev);
	~FieldValue();

	string getValue() const {return this->value;}
	FieldValue* getPrev(){return this->prev;}
	Instruction* getInstruction() const {return this->instruction;}
	int getIndex() const {return this->index;}
	
	vector<unsigned long long> queryConstraint();
	vector<unsigned long long> queryConstraintCPP(int);

	vector<unsigned long long> queryBoundary();
	vector<unsigned long long> queryBoundaryCPP(int);

	bool operator==(const FieldValue& fv) const;

	void print();
};

void writeQueryFile(stringstream& ss1, stringstream& ss2, const string& sign);
bool runZ3(unsigned long long* queryResult);
