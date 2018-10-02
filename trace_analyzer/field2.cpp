#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <cmath>

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include "z3++.h"

#include "field2.hpp"

using namespace std;

#define MAX_TRACE_LINE 5000000

vector<Field*> fields;
vector<Instruction*> instructions;
vector<string> insDisList;
vector<CheckCheksum*> insDisCheck;

ofstream output;
int insCount=0;
int queryCount = 0;

vector<Field*>::iterator findField(Field* field){
	vector<Field*>::iterator it;

	for(it = fields.begin(); it != fields.end(); it++){
		if( ((*it)->getStart() == field->getStart()) &&
			(*it)->getSize() == field->getSize())
			break;
	}

	return it;
}


bool compare(const Field* field1, const Field* field2) {
	if(field1->getSize() != field2->getSize()){
    	return (field1->getSize() < field2->getSize());
	} else {
		return (field1->getStart() < field2->getStart());
	}
}

bool compareIns(const Instruction* ins1, const Instruction* ins2) {
	return ins1->getId() < ins2->getId();
}

bool compareFieldIns(const FieldInstruction* fins1, const FieldInstruction* fins2) {
	Instruction* ins1 = fins1->getInstruction();
	Instruction* ins2 = fins2->getInstruction();

	return ins1->getId() < ins2->getId();
}

unsigned long long strToUll(string value, int size){
	string stringValue = value.substr(0, size*2);

	unsigned long long intValue = stoull(stringValue , NULL, 16);
	//reverse((char*)&intValue, ((char*)&intValue)+size);
	return intValue;
}

string ullToStr(unsigned long long value, int size){
	string result;
/*
	ss << hex << value;
	ss >> result;

	for(int i=0; result.size() < size*2; i++){
		result = "0" + result;
	}
*/

	for(int i=0; i < size; i++){
		stringstream ss;

		ss << setfill ('0') << setw(2) << hex << (int)((unsigned char*)&value)[i];
		result.append(ss.str());
		
	}

	//reverse(result.begin(), result.end());

	return result.substr(0, size*2);
}

string reversePairs(std::string const & src)
{
    assert(src.size() % 2 == 0);
    string result;
    result.reserve(src.size());

    for (std::size_t i = src.size(); i != 0; i -= 2)
    {
        result.append(src, i - 2, 2);
    }

    return result;
}

Instruction::Instruction(int id, string line){
	string strOffsets, insAddress, insDis, ins, type, operand; 
	this->id = id;

  	istringstream ss(line); 

	getline(ss, insAddress, '.');
	
	this->insAddress = insAddress;

	getline(ss, insDis, '.');

	this->insDis = insDis;
	
	istringstream ssInsDis(insDis);


	getline(ssInsDis, ins, ' ');

	if(!ins.compare("rep"))
		getline(ssInsDis, ins, ' ');

	this->ins = ins;

	getline(ss, type, '.');

	// parse operand offsets
	getline(ss, strOffsets, '.');

	this->strOffsets = strOffsets;

	strOffsets = this->strOffsets;

	string offset1 = strOffsets.substr(0, strOffsets.find("}")+1);
	
	// parse first offset
	if(offset1.size() > 3){
		this->offsets.push_back(offset1);
	}
		
	// parse second offset
	if(strOffsets.size() > offset1.size()){
		string offset2 = strOffsets.substr(offset1.size());

		if(offset2.size() > 3){
			this->offsets.push_back(offset2);
		}
		
	}

	//cout << "ins id: " << id << " ins: " << ins << " insdis: " << insDis << endl;

	// parse operand values
	for(int i=0; i < 10; i++){
		getline(ss, operand, '.');

		if(operand.empty()){
			//cout << "empty"<<endl;
			break;
		}

		// if(operand.find("0x") != string::npos){
		// //	//cout << hex << "0x" << strtoull(operand.c_str(), NULL, 16) << endl;
		// 	operand = to_string(strtoull(operand.c_str(), NULL, 16));

		// }

		//cout << i << " " << operand << " size:  " << operand.length()/2 << endl;

		if(offsets.size() > i){
			this->operands.push_back(new Operand(i, operand, offsets[i]));
		} else{
			this->operands.push_back(new Operand(i, operand));
		}

	}

}

Instruction::~Instruction(){
	vector<Operand*>::iterator itOperand;

	for(itOperand = this->operands.begin(); itOperand != this->operands.end(); itOperand++){
		delete *itOperand;
	}

}

void Instruction::proccessOffset(){
	strOffsets = this->strOffsets;

	string offset1 = strOffsets.substr(0, strOffsets.find("}")+1);
	
	// parse first offset
	// len {0x}
	if(offset1.size() > 3){

		this->makeField(offset1, 0);

	}
	
	// parse second offset
	if(strOffsets.size() > offset1.size()){
		string offset2 = strOffsets.substr(offset1.size());

		if(offset2.size() > 3){
			this->makeField(offset2, 1);
		}
		
	}

}

void Instruction::makeField(string offset, int operandIndex){
	Field* field = new Field(offset);
	vector<Field*>::iterator it;

	if(field->getSize() > 0){
		//cout << "new field" << endl;
		
		it = findField(field);

		// new field
		if(it == fields.end())
		{
			field->addInstruction(this, operandIndex);
			fields.push_back(field);

		}
		// exist field
		else
		{

			//cout << "field already exist" << endl;
			(*it)->addInstruction(this, operandIndex);
		}

		this->endian = field->getEndian();
		
	}
	else
	{
		//cout << "not a field" << endl;
		delete field;
	}
}

void Instruction::makeField(){
	vector<Operand*>::iterator itOperand;
	int operandIndex = 0;

	for (itOperand = this->operands.begin(); itOperand != this->operands.end(); itOperand++){
		Operand* op = *itOperand;
		vector<OperandField*> operandFields = op->getFields();
		vector<OperandField*>::iterator itOperandField;

		for(itOperandField = operandFields.begin(); itOperandField != operandFields.end(); itOperandField++){
			OperandField* operandField = *itOperandField;

			if(operandField->getSize() > 0){
				//cout << "[makefield] start: 0x" << operandField->getStart();
				//cout << " size: 0x" << operandField->getSize() << endl;

				Field* field = new Field(operandField);
				vector<Field*>::iterator itField;

				itField = findField(field);

				//new field
				if(itField == fields.end()){
					field->addInstruction(this, operandIndex);
					fields.push_back(field);
				}
				// exist field
				else{
					(*itField)->addInstruction(this, operandIndex);
				}

				this->endian = field->getEndian();
			}
		}

		operandIndex++;
	}

	/*
	Field* field = new Field(offset);
	vector<Field*>::iterator it;

	if(field->getSize() > 0){
		//cout << "new field" << endl;
		
		it = findField(field);

		// new field
		if(it == fields.end())
		{
			field->addInstruction(this, operandIndex);
			fields.push_back(field);

		}
		// exist field
		else
		{

			//cout << "field already exist" << endl;
			(*it)->addInstruction(this, operandIndex);
		}

		this->endian = field->getEndian();
		
	}
	else
	{
		//cout << "not a field" << endl;
		delete field;
	}
	*/
}

void Instruction::printOperands(){
	vector<Operand*>::iterator it;
	int i=0;

	for(it = operands.begin(); it != operands.end(); it++){
		cout << " op" << i << ": " << (*it)->getValue() ;
		i++;
	}
}

bool Instruction::isStringCompare(int size){
	istringstream ssInsDis(this->insDis);
	string ins;
	string op1 = this->operands[0]->getValue();
	string op2 = this->operands[1]->getValue();
	unsigned long long imm;

	getline(ssInsDis, ins, ' ');

	// cmp reg/mem, imm string
	if(!ins.compare("cmp")){
		if(ins.find(",") >= 0){

			stringstream ss(op2);

 			if(op2.find("0x") < 0 || (ss >> hex >> imm).fail()){
 				//cout << "no imm" << endl;
 			} else {
				//cout << hex << "compare " << op1 << " " << op2 << " " << imm <<  endl;
				int i;
				// if length of ascii equals with field size
				for(i = 0; i < size; i++){
					unsigned long long byte = ((imm >> (i*8)) & 0xff);
					//cout << byte << endl;
					if( (unsigned)byte > 0x7f || (unsigned)byte < 0x20 ){
						return false;
					}

					//cout << ((imm >> (i*8)) & 0xff) << endl;
				}

				if( i >= 2){
					string val((char*)&imm);
					if(this->endian == LITTLE)
						reverse(val.begin(), val.end());

					this->operands[1]->setValue(val);
					return true;
				}
 			}
		}
	}

	//else if(!ins.compare("rep")){
	//	getline(ssInsDis, ins, ' ');

		if(!ins.compare("cmpsb")){
			stringstream ss(op2);

 			if(op2.find("0x") < 0 || (ss >> hex >> imm).fail()){
 				//cout << "no imm" << endl;
 			} else {
				//cout << hex << "compare " << op1 << " " << op2 << " " << imm <<  endl;
				int i;
				// if length of ascii equals with field size
				for(i = 0; i < size; i++){
					unsigned long long byte = ((imm >> (i*8)) & 0xff);
					//cout << byte << endl;
					if( (unsigned)byte > 0x7f || (unsigned)byte < 0x20 ){
						return false;
					}

					//cout << ((imm >> (i*8)) & 0xff) << endl;
				}

				
				if( i >= 2){
					string val((char*)&imm);
					if(this->endian == LITTLE)
						reverse(val.begin(), val.end());

					this->operands[1]->setValue(val);
					return true;
				}
 			}

			return true;
		} 
	//}

	return false;
}

bool Instruction::operator==(const Instruction& ins) const {
	cout << "[Instruction ==] " << this->getInsDis() << " " << ins.getInsDis() << endl;

	vector<Operand*> operands = ins.getOperands(); 

	if(this->operands.size() != operands.size()) return false;
	for(int i=0; i<this->operands.size(); i++){
		if(this->operands[i]->getValue().compare(operands[i]->getValue()))
			return false;
	}

	return (this->insDis == ins.getInsDis());
}

Field::Field(){

}

Field::Field(string strOffsets){
	strOffsets = strOffsets.substr(1, strOffsets.size()-2);
	//cout << "field: " << strOffsets << endl;
	

	string strOffset; 
	string::size_type sz = 0;

    istringstream ss(strOffsets); 

    this->start = -1;
    this->size = 0;
    this->type = NONE;
    this->endian = BIG;
    this->end = 0;

    int direction = 0;

	while(getline(ss, strOffset, ',')) {	
		if( !strOffset.empty()){
			unsigned long long offset = stoull(strOffset, &sz, 0);

			// first offset
			if(this->start == -1){
				this->start = offset;
				this->end = offset;
				this->size = 1;
			}
			// increse offset
			else if(this->end + 1 == offset && direction != -1)
			{
				direction = 1;

				this->end = offset;
				this->size++;
			}
			//decrese offset
			else if(this->end - 1 == offset && direction != 1)
			{
				direction = -1;

				this->end = offset;
				this->size++;
				this->endian = LITTLE;
			}

			else
			{
				if(size >= 2 && size <= 16){
					//cout << "it's a field" << endl;
					break;
				}

				this->size = -1; // not a field
				return ;
			}
		}
	}

	if(this->endian == LITTLE){
		this->start = this->end;	
		this->end = this->start + this->size;
	}
}

Field::Field(OperandField* operandField){
	this->start = operandField->getStart();
	this->end = operandField->getEnd();
	this->size = operandField->getSize();
	this->type = NONE;
	this->endian = operandField->getEndian();

	//cout << hex << "[Field] start: 0x" << this->start;
	//cout << " size: 0x" << this->size << endl;
}

Field::~Field(){

}

void Field::addInstruction(Instruction* ins, int index){
	//if(!this->isInstructionExist(ins)){
	this->instructions.push_back(new FieldInstruction(ins, index));
	//}
}
/*
bool Field::isInstructionExist(Instruction* ins){
	vector<FieldInstruction*>::iterator it;

	for(it = this->instructions.begin(); it != this->instructions.end(); it++){
		if((*(*it)->getInstruction()) == *ins){
			return true;
		}
	}

	return false;
}
*/
bool Field::isMarkerExist(string marker){
	vector<string>::iterator i;

	for(i = markers.begin(); i != markers.end(); i++){
		if((*i) == marker)
			return true;
	}

	return false;
}

bool Field::isConstraintExist(string constraint){
	vector<string>::iterator i;

	for(i = constraints.begin(); i != constraints.end(); i++){
		if((*i) == constraint)
			return true;
	}

	return false;
}

bool Field::isInterestExist(string interest){
	vector<string>::iterator i;

	for(i = interests.begin(); i != interests.end(); i++){
		if((*i) == interest)
			return true;
	}

	return false;
}

FieldValue* Field::getFieldValue(string value) {
	vector<FieldValue*>::iterator it;
	FieldValue* fv = NULL;

	for(it = this->values.begin(); it != this->values.end(); it++){
		if(!(*it)->getValue().compare(value)){
			//return (*it);
			fv = *it;
		}
	}

	// return last field value
	return fv;
}

void Field::addValue(FieldValue* fv){

	if(!this->isFieldValueExist(fv)){
		this->values.push_back(fv);
	}
	else{
		delete fv;
	}

}

bool Field::isFieldValueExist(FieldValue* fv){
	vector<FieldValue*>::iterator it;

	for(it = this->values.begin(); it != this->values.end(); it++){
		FieldValue* curFv = *it;

		if(*curFv == *fv){
			return true;
		}
	}

	return false;
}


void Field::print(){
	if( this->markers.size() == 0 && this->constraints.size() == 0 && this->interests.size() == 0)
		return;
	
	output << this->start << "\t" << this->size << "\t";

	vector<string>::iterator itStr;

	output << "M";
	for(itStr = this->markers.begin(); itStr != this->markers.end(); itStr++){
		output << (*itStr).substr(0, this->size * 2);
		if(itStr+1 == this->markers.end()) break;
		output << ",";
	}

	output << "\tC";
	for(itStr = this->constraints.begin(); itStr != this->constraints.end(); itStr++){
		output << (*itStr).substr(0, this->size * 2);
		if(itStr+1 == this->constraints.end()) break;

		output << ",";
	}

	output << "\tI";
	for(itStr = this->interests.begin(); itStr != this->interests.end(); itStr++){
		output << (*itStr).substr(0, this->size * 2);
		if(itStr+1 == this->interests.end()) break;

		output << ",";
	}

	output << endl;
}

Operand::Operand(){

}

Operand::Operand(int id, string operand){
	this->index = index;
	this->value = operand;
	this->size = operand.length()/2;
	this->isTaint = false;

	//if( strOffset)
	//cout << "Operand " << strOffset << endl;
}

Operand::Operand(int id, string operand, string strOffsets){
	string strOffset;
	strOffsets = strOffsets.substr(1, strOffsets.size()-2);

	this->index = index;
	this->value = operand;
	this->size = operand.length()/2;
	this->isTaint = true;

	//if( !strOffsets.empty())
	//	cout << "[Operand] strOffsets: " << strOffsets << endl;

	
	string::size_type sz = 0;

    istringstream ss(strOffsets); 

    int start = -1;
    int size = 0;
    int type = NONE;
    int endian = BIG;
    int end = 0;

    int direction = 0;
    int operandOffset = 0;

	while(getline(ss, strOffset, ',')) {	
		//cout << "[Operand] strOffset: " << strOffset << endl;
		if( !strOffset.empty()){
			unsigned long long offset = stoull(strOffset, &sz, 0);

			// first offset
			if(start == -1){
				start = offset;
				end = offset;
				size = 1;
			}
			// increse offset
			else if(end + 1 == offset && direction != -1)
			{
				direction = 1;

				end = offset;
				size++;
			}
			//decrese offset
			else if(end - 1 == offset && direction != 1)
			{
				direction = -1;

				end = offset;
				size++;
				endian = LITTLE;
				//cout << "[Operand] Little endian" << endl; 
			}

			else
			{
				if(size >= 2 && size <= 16){
					if(endian == LITTLE){
						start = end;	
						end = start + size;
					}

					//cout << "it's a multiple field" << endl;
					this->operandFields.push_back(new OperandField(start, end, size, operandOffset-size, endian));
				}

				start = offset;
			    size = 1;
			    type = NONE;
			    endian = BIG;
			    end = offset;
			    direction = 0;
			}
		}

		operandOffset++;
	}

	if(endian == LITTLE){
		start = end;	
		end = start + size;
	}

	//cout << "it's a last field" << endl;
	this->operandFields.push_back(new OperandField(start, end, size, operandOffset-size, endian));
}

Operand::~Operand(){

}

int Operand::getFieldOffset(int start, int size) {
	vector<OperandField*>::iterator it;

	cout << "[Operand::getFieldOffset] Field start: " << start << " size: " << size << endl;

	for(it = this->operandFields.begin(); it != this->operandFields.end(); it++){
		if((*it)->getSize() == size && (*it)->getStart() == start){
			cout << "[Operand::getFieldOffset] Field found at " << (*it)->getOffset() << endl;
			return (*it)->getOffset();
		}
	}

	cout << "[Operand::getFieldOffset] No such field!" << endl;
	return -1;
}

OperandField::OperandField(){

}

OperandField::OperandField(int start, int end, int size, int offset, int endian){
	//cout << hex << "[OperandField] start: 0x" << start << " size: 0x" << size << " offset: 0x" << offset << endl;
	this->start = start;
	this->end = end;
	this->size = size;
	this->offset = offset;
	this->endian = endian;
}

OperandField::~OperandField(){

}


CheckCheksum::CheckCheksum(string insDis, int insAddr){
	this->insDis = insDis;
	this->insAddr = insAddr;
}

CheckCheksum::~CheckCheksum(){
	this->offsets.clear();

	vector<Instruction*>::iterator itInstructions;

	for(itInstructions = this->instructions.begin(); itInstructions != this->instructions.end(); itInstructions++){
		delete *itInstructions;
	}

	this->instructions.clear();
}

bool CheckCheksum::isChecksum(){
	vector<string>::iterator it;

	int count = 0;
	int start = 0;
	int prevStart = Field(offsets[0]).getStart();
	int gap = 1;
	//int next = start + gap;

	for(it = offsets.begin()+1; it != offsets.end(); it++){
		//cout << hex << *it << " start:"  << Field(*it).getStart() << endl;

		start = Field(*it).getStart();

		//cout << "[ischecksum] start: " << start << " count: " << count << " gap: " << gap << endl;

		if(gap != (start - prevStart)){
			gap = start - prevStart;
			count = 0;
		}
		else
		{
			count++;
		}

		if(count > 16)
			return true;

		prevStart = start;
	}

	return false;
}

bool FieldValue::operator==(const FieldValue& fv) const {

	if(this->value == fv.getValue() &&
		this->instruction == fv.getInstruction() &&
		this->index == fv.getIndex()){

		return true;
	}

	return false;
}



vector<unsigned long long> FieldValue::queryConstraintCPP(int type){
	FieldValue* prev = this->prev;
	string ins;
	unsigned long long opTaint;
	unsigned long long op;

	vector<FieldValue*> list;

	//list.push_back(this);

	while(prev != NULL){
		list.push_back(prev);

		prev = prev->prev;
	}

	reverse(list.begin(), list.end());

	vector<FieldValue*>::iterator it;

	cout << "[query constraint] current fvalue: " << this->getValue() << " ins: " << this->getInstruction()->getInsDis();
	cout << " taint value: " << opTaint << endl;

	cout << "[query constraint] fvalue list" << endl;

	for(it = list.begin(); it != list.end(); it++){
		FieldValue* fv = *it;

		ins = fv->getInstruction()->getInsDis();

		opTaint = fv->getInstruction()->getOperands()[0]->getValueInt(this->value.length()/2);


		cout << "\tfvalue: " << fv->getValue() << " ins: " << ins;
		cout << " taint value: " << opTaint << endl;
	}

	z3::context   *z3Context;
	z3::expr      *z3Var;
	z3::solver    *z3Solver;
	z3::expr      *z3Equation;
	z3::model     *z3Model;

    z3Context   = new z3::context;
    z3Var       = new z3::expr(z3Context->bv_const("x", 64));
    z3Solver    = new z3::solver(*z3Context);
    z3Equation  = new z3::expr(*z3Var);

	for(it = list.begin(); it != list.end(); it++){
		FieldValue* fv = *it;

		ins = fv->getInstruction()->getIns();


		if( !ins.compare("add") || !ins.compare("sub") ||
			!ins.compare("imul") || !ins.compare("mul") ||
			!ins.compare("div") || !ins.compare("idiv") ||
			!ins.compare("or") || !ins.compare("and") ||
			!ins.compare("xor") || !ins.compare("not") ||
			!ins.compare("inc") || !ins.compare("dec") ||
			!ins.compare("shr") || !ins.compare("shl") ||
			!ins.compare("sar") || !ins.compare("sal") ||
			!ins.compare("cmp")
			)
		{
			op = fv->getInstruction()->getOperands()[(index+1)%2]->getValueInt(this->value.length()/2);

			if ( !ins.compare("add"))
			{
				*z3Equation = (*z3Equation + static_cast<int>(op));

			}
			 else if( !ins.compare("sub"))
			{
				*z3Equation = (*z3Equation - static_cast<int>(op));
			} else if( !ins.compare("imul") || !ins.compare("mul")){
				if(fv->getInstruction()->getOperands().size() == 3)
					op = fv->getInstruction()->getOperands()[2]->getValueInt(this->value.length()/2);

				*z3Equation = (*z3Equation * static_cast<int>(op));

			} 
			else if( !ins.compare("div") || !ins.compare("idiv"))
			{	
				*z3Equation = (*z3Equation / static_cast<int>(op));
			}
			else if( !ins.compare("shl"))
			{
				*z3Equation = (*z3Equation * static_cast<int>(pow(2, op)));
			}
			else if( !ins.compare("shr") || !ins.compare("sar")) 
			{
				*z3Equation = (*z3Equation / static_cast<int>(pow(2, op)));
			} 
			else if(!ins.compare("or"))
			{
				*z3Equation = (*z3Equation | static_cast<int>(op));
			} 
			else if(!ins.compare("and")){
				*z3Equation = (*z3Equation & static_cast<int>(op));
			} 
			else if(!ins.compare("xor")){
				*z3Equation = (*z3Equation ^ static_cast<int>(op));
			}
			else if(!ins.compare("inc")){
				*z3Equation = (*z3Equation + static_cast<int>(1));
			}
			else if(!ins.compare("dec")){
				*z3Equation = (*z3Equation - static_cast<int>(1));
			}
			else if ( !ins.compare("cmp")){
				cout << "\t[cmp] " << op << " " << opTaint << endl;	
				if( op > opTaint)
					*z3Equation = (*z3Equation > static_cast<int>(op));
				else if( op < opTaint)
					*z3Equation = (*z3Equation < static_cast<int>(op));
				else
					*z3Equation = (*z3Equation == static_cast<int>(op));

				z3Solver->add(*z3Equation);

				delete z3Equation;

	    		z3Equation  = new z3::expr(*z3Var);

			}
		}
		else {

			cout << "[query constraint] not support instruction" << endl;
			vector<unsigned long long> results;

			return results;
		}

		cout << "[query constraint] " << fv->getValue() << " ins: " << ins << " " << opTaint << endl;

	}	

	unsigned long long queryResult = 0;
	vector<unsigned long long> results;

	//ssQuery2 << this->getInstruction()->getOperands()[(index+1)%2]->getValueInt(this->value.length()/2);
	op = this->getInstruction()->getOperands()[(index+1)%2]->getValueInt(this->value.length()/2);

	switch(type){
		case 0: *z3Equation = (*z3Equation == static_cast<int>(op)); break;
		case 1:	*z3Equation = (*z3Equation > static_cast<int>(op)); break;
		case 2:	*z3Equation = (*z3Equation < static_cast<int>(op)); break;
		default: break;
	}

	z3Solver->add(*z3Equation);

try{
	switch(z3Solver->check()){
	case z3::unsat:	//cout << "unsat" << endl; 
		break;

	case z3::sat:
		queryCount++;

		z3Model = new z3::model(z3Solver->get_model());
	 	cout << "[query constraint] solver: " << Z3_solver_to_string(*z3Context, *z3Solver) << endl;
		cout << "[query constraint] model: " << Z3_model_to_string(*z3Context, *z3Model) << endl;

		unsigned long long goodValue; 
		Z3_get_numeral_uint64(*z3Context, z3Model->get_const_interp((*z3Model)[0]), &goodValue); 

		results.push_back(goodValue);

		delete z3Model;
		break;

	case z3::unknown: //cout << "unknown" << endl;	
		break;
	}
}
catch (z3::exception e) {
	cout << "[query constraint] faield.\t" << e.msg() << endl;
}
    	/*
	for(int i=0; i < 3; i++){
		z3::solver    *z3Solver2 = new z3::solver(*z3Solver);
		z3::expr      *z3Equation2;
    	z3Equation2  = new z3::expr(*z3Equation);

		switch(i){
		case 0: *z3Equation2 = (*z3Equation == static_cast<int>(op)); break;
		case 1:	*z3Equation2 = (*z3Equation > static_cast<int>(op)); break;
		case 2:	*z3Equation2 = (*z3Equation < static_cast<int>(op)); break;
		default: break;
		}

		z3Solver2->add(*z3Equation2);

		switch(z3Solver2->check()){
		case z3::unsat:	//cout << "unsat" << endl; 
			break;

		case z3::sat:
			z3Model = new z3::model(z3Solver2->get_model());
		 	cout << "[query constraint] solver: " << Z3_solver_to_string(*z3Context, *z3Solver2) << endl;
			cout << "[query constraint] model: " << Z3_model_to_string(*z3Context, *z3Model) << endl;

			unsigned long long goodValue; 
			Z3_get_numeral_uint64(*z3Context, z3Model->get_const_interp((*z3Model)[0]), &goodValue); 

			results.push_back(goodValue);

			delete z3Model;
			break;

		case z3::unknown: //cout << "unknown" << endl;	
			break;
		}
	
		delete z3Equation2;
		delete z3Solver2;
	}*/

	delete z3Equation;
	delete z3Var;
	delete z3Solver;
	delete z3Context;

	return results;
}

vector<unsigned long long> FieldValue::queryBoundaryCPP(int type){
	FieldValue* prev = this->prev;
	string ins;
	unsigned long long opTaint;
	unsigned long long op;

	vector<FieldValue*> list;

	//list.push_back(this);

	cout << "[query boundary] current fvalue: " << this->getValue() << " ins: " << this->getInstruction()->getInsDis();
	cout << " taint value: " << opTaint << endl;

	while(prev != NULL){
		list.push_back(prev);

		prev = prev->prev;
	}

	reverse(list.begin(), list.end());

	vector<FieldValue*>::iterator it;

	cout << "[query boundary] fvalue list" << endl;

	for(it = list.begin(); it != list.end(); it++){
		FieldValue* fv = *it;

		ins = fv->getInstruction()->getInsDis();

		opTaint = fv->getInstruction()->getOperands()[0]->getValueInt(this->value.length()/2);

		cout << "\tfvalue: " << fv->getValue() << " ins: " << ins;
		cout << " taint value: " << opTaint << endl;

	}

	z3::context   *z3Context;
	z3::expr      *z3Var;
	z3::solver    *z3Solver;
	z3::expr      *z3Equation;
	z3::model     *z3Model;

    z3Context   = new z3::context;
    z3Var       = new z3::expr(z3Context->bv_const("x", 64));
    z3Solver    = new z3::solver(*z3Context);
    z3Equation  = new z3::expr(*z3Var);

	for(it = list.begin(); it != list.end(); it++){
		FieldValue* fv = *it;

		ins = fv->getInstruction()->getIns();

		if( !ins.compare("add") || !ins.compare("sub") ||
			!ins.compare("imul") || !ins.compare("mul") ||
			!ins.compare("div") || !ins.compare("idiv") ||
			!ins.compare("or") || !ins.compare("and") ||
			!ins.compare("xor") || !ins.compare("not") ||
			!ins.compare("inc") || !ins.compare("dec") ||
			!ins.compare("shr") || !ins.compare("shl") ||
			!ins.compare("sar") || !ins.compare("sal") ||
			!ins.compare("cmp")
			)
		{
			op = fv->getInstruction()->getOperands()[(index+1)%2]->getValueInt(this->value.length()/2);

			if ( !ins.compare("add"))
			{
				*z3Equation = (*z3Equation + static_cast<int>(op));

			}
			 else if( !ins.compare("sub"))
			{
				*z3Equation = (*z3Equation - static_cast<int>(op));
			} else if( !ins.compare("imul") || !ins.compare("mul")){
				if(fv->getInstruction()->getOperands().size() == 3)
					op = fv->getInstruction()->getOperands()[2]->getValueInt(this->value.length()/2);

				*z3Equation = (*z3Equation * static_cast<int>(op));

			} 
			else if( !ins.compare("div") || !ins.compare("idiv"))
			{	
				*z3Equation = (*z3Equation / static_cast<int>(op));
			}
			else if( !ins.compare("shl"))
			{
				*z3Equation = (*z3Equation * static_cast<int>(pow(2, op)));
			}
			else if( !ins.compare("shr") || !ins.compare("sar")) 
			{
				*z3Equation = (*z3Equation / static_cast<int>(pow(2, op)));
			} 
			else if(!ins.compare("or"))
			{
				*z3Equation = (*z3Equation | static_cast<int>(op));
			} 
			else if(!ins.compare("and")){
				*z3Equation = (*z3Equation & static_cast<int>(op));
			} 
			else if(!ins.compare("xor")){
				*z3Equation = (*z3Equation ^ static_cast<int>(op));
			}
			else if(!ins.compare("inc")){
				*z3Equation = (*z3Equation + static_cast<int>(1));
			}
			else if(!ins.compare("dec")){
				*z3Equation = (*z3Equation - static_cast<int>(1));
			}
			else if ( !ins.compare("cmp")){
				cout << "\t[cmp] " << op << " " << opTaint << endl;	
				if( op > opTaint)
					*z3Equation = (*z3Equation > static_cast<int>(op));
				else if( op < opTaint)
					*z3Equation = (*z3Equation < static_cast<int>(op));
				else
					*z3Equation = (*z3Equation == static_cast<int>(op));

				z3Solver->add(*z3Equation);

				delete z3Equation;

	    		z3Equation  = new z3::expr(*z3Var);

			}
		}
		else {

			cout << "[query boundary] not support instruction" << endl;
			vector<unsigned long long> results;

			return results;
		}

		cout << "[query boundary] " << fv->getValue() << " ins: " << ins << " " << opTaint << endl;

	}	

	string sign;
	stringstream ssQuery2;

	index = this->index;

	ins = this->getInstruction()->getIns();

	if( !ins.compare("add") || !ins.compare("sub") ||
			!ins.compare("imul") || !ins.compare("mul") ||
			!ins.compare("shl")
			)
	{
		int opCount = this->getInstruction()->getOperands().size();

		op = this->getInstruction()->getOperands()[(index+1)%2]->getValueInt(this->value.length()/2);

		cout << "[query boundary] Boundary - ins : " << ins <<  " index: " << index << endl;
		
		if(ins == "add" || ins == "mul" || ins == "imul" || ins == "shl"){
			if(ins == "add"){
				*z3Equation = (*z3Equation + static_cast<int>(op));

			}  else if(ins == "mul"){
				*z3Equation = (*z3Equation * static_cast<int>(op));

			} else if(ins == "imul"){
				if(opCount > 3){
					if(index == 1){
						op = this->getInstruction()->getOperands()[2]->getValueInt(this->value.length()/2);

					*z3Equation = (*z3Equation * static_cast<int>(op));

					} 
				} else if(opCount == 2){
					cout << "[query boundary] \t";

					this->getInstruction()->printOperands();

					cout << hex << "\t\t" << op << endl;

					*z3Equation = (*z3Equation * static_cast<int>(op));

				} else {
					//temp
					*z3Equation = (*z3Equation * static_cast<int>(op));
				}

			} else if(ins == "shl"){
				*z3Equation = (*z3Equation * static_cast<int>(pow(2, op)));

			}

			if(type == SIO)
				*z3Equation = (*z3Equation > static_cast<int>(0x7fffffff));
			else if(type == UIO){
				*z3Equation = (*z3Equation / static_cast<int>(2));				
				*z3Equation = (*z3Equation > static_cast<int>(0x7fffffff));
			}


		} else if(ins == "sub"){
			*z3Equation = (*z3Equation + static_cast<int>(op));
			*z3Equation = (*z3Equation < 0);
		}
	}
	else {

			//cout << "[query boundary] ins: " << ins << endl;
			vector<unsigned long long> results;

			return results;
	}

	unsigned long long queryResult = 0;
	vector<unsigned long long> results;

	z3Solver->add(*z3Equation);

try{
	switch(z3Solver->check()){
	case z3::unsat:	//cout << "unsat" << endl; 
		break;

	case z3::sat:
		queryCount++;
		z3Model = new z3::model(z3Solver->get_model());

	 	cout << "[query boundary] solver: " << Z3_solver_to_string(*z3Context, *z3Solver) << endl;
		cout << "[query boundary] model: " << Z3_model_to_string(*z3Context, *z3Model) << endl;

		unsigned long long goodValue; 
		Z3_get_numeral_uint64(*z3Context, z3Model->get_const_interp((*z3Model)[0]), &goodValue); 

		cout << hex << "[query boundary] result: " << goodValue << endl;

		results.push_back(goodValue);

		delete z3Model;
		break;

	case z3::unknown: //cout << "unknown" << endl;	
		break;
	}

}
catch (z3::exception e) {
	cout << "[query boundary] faield.\t" << e.msg() << endl;
}

	delete z3Equation;
	delete z3Var;
	delete z3Solver;
	delete z3Context;

	return results;
}

void FieldValue::print(){
	cout << "FieldValue";

	cout << "\tinstruction: " << this->instruction->getInsDis() << " value: " << this->value << endl;

}

void removeChecksumByInsDis(){
	vector<Instruction*>::iterator itInstruction;
	vector<string>::iterator itInsDis;
	string insDis, insDis2;

	for(itInsDis = insDisList.begin(); itInsDis != insDisList.end(); itInsDis++){
		//cout << (*itInsDis) << endl;
		string curIns = (*itInsDis);
    	
		for(itInstruction = instructions.begin(); itInstruction != instructions.end(); itInstruction++){
	    	Instruction* instruction = *itInstruction;
	    	vector<string> offsets = instruction->getOffsets();
	    	vector<string>::iterator it;

	    	for(it = offsets.begin(); it != offsets.end(); it++){
	    	}
    	}
		
	}
}

FieldValue::FieldValue(Instruction* instruction, int index, string value, FieldValue* prev){
	this->instruction = instruction;
	this->index = index;
	this->value = value;
	this->prev = prev;
	cout << "[FieldValue] ins: " << instruction->getIns() << " index: " << index;

	if(prev != NULL){
		cout << "\tprev ins: " << prev->getInstruction()->getIns() << endl;
	}
}

FieldValue::~FieldValue(){

}

int main(int argc, char** argv){
	ifstream trace;
	string line;

	if( argc < 3){
		//cout << "usage: ./field [trace file] [input data]" << endl;
		exit(1);
	}

	output.open("field.out");

    std::ifstream input( argv[2], std::ios::binary );
    // copies all data into buffer
    std::vector<unsigned char> inputData((
            std::istreambuf_iterator<char>(input)), 
            (std::istreambuf_iterator<char>()));

    
	//read trace file
	trace.open(argv[1], ios::in);

	int instructionId = 0;
	int instructionCount = 0;
	int lineCount = 0;

	while( getline(trace, line) ){
		if(line.back() != '.')
			break;

		//if(line.find("mov") == string::npos){
			if(lineCount > MAX_TRACE_LINE) break;
			
			lineCount++;
			
			Instruction* instruction = new Instruction(instructionId, line);
	    	vector<string>::iterator it;

	    	instructionId++;

			vector<string> offsets = instruction->getOffsets();
	    	
	    	bool isContinuous = false;

			cout << "insdis: " << instruction->getInsDis();

	    	for (int i=0; i < offsets.size(); i++){
	    		cout << " " << offsets[i];
	    	}

	    	cout << endl;

	    	//remove no continuous offset
	    	for(it = offsets.begin(); it != offsets.end(); it++){
	    		Field field(*it);

	    		if(field.getSize() > 0){
	    			isContinuous = true;
	    		}
	    	}

	    	if(isContinuous == true){
	    		//instructions.push_back(instruction);

		    	string insDis = instruction->getInsDis();
		    	int insAddr = strToUll(instruction->getInsAddress().substr(2, sizeof(int)*2), sizeof(int));

 		    	it = find(insDisList.begin(), insDisList.end(), insDis);

				if(it == insDisList.end()){
		    		insDisList.push_back(insDis);
		    		//cout << "new insDis: " << insDis << endl;

		    	}

	    		// grouping by instruction
		    	vector<CheckCheksum*>::iterator itCheck;

		    	// find by insAddress
		    	for(itCheck = insDisCheck.begin(); itCheck != insDisCheck.end(); itCheck++){
		    		if((*itCheck)->getInsAddr() == insAddr)
		    			break;
		    	}

		    	// new Checkcheksum
		    	if(itCheck == insDisCheck.end()){
		    		CheckCheksum* check = new CheckCheksum(insDis, insAddr);
		    		check->addOffsets(offsets[0]);
		    		//cout << "check: " << offsets[0] << endl;
		    		check->addInstruction(instruction);
		    		insDisCheck.push_back(check);
		    		instructionCount++;
		    	}
		    	else{
		    		(*itCheck)->addOffsets(offsets[0]);
		    		//cout << "check: " << offsets[0] << endl;
		    		(*itCheck)->addInstruction(instruction);
		    		instructionCount++;
		    	}
		    }
		    else{
		    }
    	//}
	}

	cout << "[Trace Reduce] before ins count: " << instructionCount << endl;
	//removeChecksumByInsDis();

	vector<CheckCheksum*>::iterator itCheck;

	// find checksum instruction
	for(itCheck = insDisCheck.begin(); itCheck != insDisCheck.end(); ){
		CheckCheksum* check = *itCheck;

		if(!check->isChecksum()){
			vector<Instruction*> checkInss = check->getInstructions();

			instructions.insert(instructions.end(), checkInss.begin(), checkInss.end());

			itCheck++;
		} else {
			delete check;

			itCheck = insDisCheck.erase(itCheck);
		}
	}

	//cout << "[Trace Reduce] after insDis count: " << insDisList.size() << endl;

	insDisCheck.clear();

	cout << "Delete checksum instructions finished." << endl;

	vector<Instruction*>::iterator itIns;

	cout << "[Process Field Offset] before ins count: " << instructions.size() << endl;;

	for(itIns = instructions.begin(); itIns != instructions.end(); ){
		// except mov instruction
		if((*itIns)->getIns().find("mov") == string::npos){
			//(*itIns)->proccessOffset();
			(*itIns)->makeField();

			itIns++;
		}
		else{
			delete *itIns;

			itIns = instructions.erase(itIns);
		}

	}

	cout << "[Process Field Offset] after ins count: " << instructions.size() << endl;;

	cout << "Process field offset finished." << endl;


	sort(fields.begin(), fields.end(), compare);

	vector<Field*>::iterator itField;

	cout << "field information" << endl;

	// print field information
	for(itField = fields.begin(); itField != fields.end(); itField++){
		cout << "start: " << (*itField)->getStart() << "\tsize: " << (*itField)->getSize() << "\t" << endl;

		cout << "orig value: ";

		for(int j=0; j < (*itField)->getSize(); j++){
			//printf("%02x", (unsigned int)inputData[(*itField)->getStart() + j]);
			cout << hex << (unsigned int)inputData[(*itField)->getStart() + j];
		}

		cout << endl;

		vector<FieldInstruction*> fieldInss = (*itField)->getInstructions();
		vector<FieldInstruction*>::iterator itInss;

		sort(fieldInss.begin(), fieldInss.end(), compareFieldIns);

		for(itInss = fieldInss.begin(); itInss != fieldInss.end(); itInss++){
			Instruction* ins = (*itInss)->getInstruction();
			int index = (*itInss)->getIndex();


			cout << "\t\t"  << ins->getId() << " " << ins->getInsDis() << " \t";
			cout << "endian: " << ins->getEndianStr() << "\t";

			ins->printOperands();
			cout << " t op: " << index;

			cout << endl;
		}

	}

	cout << "Make field finished." << endl;


	// get marker
	for(itField = fields.begin(); itField != fields.end(); itField++){
		Field* field = *itField;
		int start = field->getStart();
		int size = field->getSize();

		vector<FieldInstruction*> fIns = (*itField)->getInstructions();
		vector<FieldInstruction*>::iterator itFIns;

		//set original value
		string value;

		for(int i=0; i < size; i++){
			stringstream ss;

			ss << setfill ('0') << setw(2) << hex << (int)inputData[start+i];
			
			value.append(ss.str());
			
		}

		field->setOriginalValue(value);

		//cout << "field start: " << start << " size: " << size << endl;; 
		
		sort(fIns.begin(), fIns.end(), compareFieldIns);

		for(itFIns = fIns.begin(); itFIns != fIns.end(); itFIns++){

			Instruction* instruction = (*itFIns)->getInstruction();
			int index = (*itFIns)->getIndex();

			string ins = instruction->getIns();
			vector<Operand*> operands = instruction->getOperands();

			Operand* taintOp = operands[index];
			
			Operand* operand;

			if(index == 0){
				operand = operands[1];
			}
			else if(index == 1)
			{
				operand = operands[0];
			}
			else{
				abort();
			}
				
			string taintValue = taintOp->getValue(size);

			//cout << ins << ": " << taintValue << " " << value << endl;

			if(ins.find("cmp") != string::npos && !taintValue.compare(value)){
				// add new marker
				if( !field->isMarkerExist(operand->getValue())){
					field->addMarker(operand->getValue());

					//cout << "\tnew marker: " << operand->getValue() << endl;
				}
				else{

				}
			}
		}
	}

	cout << "field count: " << fields.size() << endl;
	cout << "\n\n\n\n";

	// make field tree
	for(itField = fields.begin(); itField != fields.end(); itField++){
		Field* field = *itField;
		int start = field->getStart();
		int size = field->getSize();
		string orig = field->getOrignalValue();

		vector<FieldInstruction*> fIns = (*itField)->getInstructions();
		vector<FieldInstruction*>::iterator itFIns;

		cout << "field start: " << start << " size: " << size << endl;

		sort(fIns.begin(), fIns.end(), compareFieldIns);

		vector<FieldInstruction*> fIns2;


		for(itFIns = fIns.begin(); itFIns != fIns.end(); itFIns++){
			if(find(fIns2.begin(), fIns2.end(), *itFIns) != fIns2.end()) continue;

			fIns2.push_back(*itFIns);

			Instruction* instruction = (*itFIns)->getInstruction();
			int index = (*itFIns)->getIndex();

			string ins = instruction->getIns();
			vector<Operand*> operands = instruction->getOperands();

			int tOperandSize = operands[index]->getSize();

			if((*itFIns)->getInstruction()->getEndian() == LITTLE){
				orig = reversePairs(orig);
			}

			if(!ins.compare("add") ||
			// !ins.compare("adc") ||
			//	!ins.compare("sbb") || 
				!ins.compare("sub") ||
			//	!ins.compare("addsd") || !ins.compare("subsd") ||
				!ins.compare("mul") || !ins.compare("imul") ||
				!ins.compare("div") || !ins.compare("idiv") ||
				!ins.compare("or") || !ins.compare("and") || 
				!ins.compare("xor") || !ins.compare("not") ||
				!ins.compare("inc") || !ins.compare("dec") ||
				!ins.compare("shr") || !ins.compare("shl") ||
				!ins.compare("sar") || !ins.compare("sal") ||
				!ins.compare("cmp")
				)
			{
				cout << "\tins: " << ins << " orig: " << orig;
				cout << " taint op: " << operands[index]->getValue(size);
				cout << " taint op: " << operands[index]->getValue(operands[index]->getSize());
				
				if(operands.size() > 1){
					cout << " other op: " << operands[(index+1)%2]->getValue(size) << endl;
				}

				FieldValue* fieldValue = NULL;
				
				string taintValue = operands[index]->getValue(operands[index]->getSize());

				int offset = operands[index]->getFieldOffset(start, size);

				// get taint value offset 

				cout << "taint val: " << taintValue << " field val: "<< taintValue.substr(offset*2, size*2) << endl;

				if(!taintValue.substr(offset*2, size*2).compare(orig) ||
					(fieldValue = field->getFieldValue(taintValue)) != NULL){
					cout << "\ttrue" << endl;

					if(!ins.compare("add") || 
						//!ins.compare("adc") ||
						//!ins.compare("sbb") || 
						!ins.compare("sub") ||
						//!ins.compare("addsd") || !ins.compare("subsd") ||
						!ins.compare("mul") ||
						!ins.compare("or") || !ins.compare("and") ||
						!ins.compare("xor") || 
						!ins.compare("shr") || !ins.compare("shl") ||
						!ins.compare("sar") || !ins.compare("sal")
						)
					{
						int operandSize2 = operands[(index+1)%2]->getSize();


						unsigned long long op1 = operands[index]->getValueInt(tOperandSize);
						unsigned long long op2 = operands[(index+1)%2]->getValueInt(operandSize2);

						//cout << hex <<"\t" << ins << " op1: " << op1 << " op2: " << op2 << " result: " << op1+op2 << endl;
						
						unsigned long long result = 0;

						if(!ins.compare("add"))
							result = op1 + op2;
						else if(!ins.compare("sub"))
							result = op1 - op2;
						else if(!ins.compare("shl"))
							result = op1 << op2;
						else if(!ins.compare("shr"))
							result = op1 >> op2;
						else if(!ins.compare("sar"))
							result = (signed)op1 >> (signed)op2;
						else if(!ins.compare("sal"))
							result = (signed)op1 << (signed)op2;
						else if(!ins.compare("and"))
							result = op1 & op2;
						else if(!ins.compare("or"))
							result = op1 | op2;
						else if(!ins.compare("xor"))
							result = op1 ^ op2;
						else if(!ins.compare("mul"))
							result = (unsigned)op1 * (unsigned)op2;

						int resultSize = (tOperandSize > operandSize2) ? tOperandSize : operandSize2;

						string strResult = ullToStr(result, resultSize);
						
						field->addValue(new FieldValue(instruction, index, strResult, fieldValue));	
					}

					else if(!ins.compare("imul"))
					{
						int opCount = operands.size();

						if(opCount == 3){
							//cout << "\toperand count: " << operands.size() << endl;

							if(index == 3){
								int operandSize1 = operands[0]->getSize();
								int operandSize2 = operands[1]->getSize();
								int operandSize3 = operands[2]->getSize();

								unsigned long long op1 = operands[0]->getValueInt(operandSize1);
								unsigned long long op2 = operands[1]->getValueInt(operandSize2);
								unsigned long long op3 = operands[2]->getValueInt(operandSize3);

								//cout << hex <<"\t" << ins << " op2: " << op2 << " op3: " << op3 << "result: ";
								long long result = op2 * op3;

								int resultSize = (operandSize1 > operandSize2) ? operandSize1 : operandSize2;
								resultSize = (resultSize > operandSize3) ? resultSize : operandSize3;

								string strResult = ullToStr(result, resultSize);

								//cout << strResult << endl;

								field->addValue(new FieldValue(instruction, index, strResult, fieldValue));
							}
						}
						else if(opCount == 2){
								int operandSize1 = operands[0]->getSize();
								int operandSize2 = operands[1]->getSize();

								unsigned long long op1 = operands[index]->getValueInt(operandSize1);
								unsigned long long op2 = operands[(index+1)%2]->getValueInt(operandSize2);

								cout << hex << "\t" << ins << " op1: "<< op1 << " op2: " << op2 << " result: ";
								long long result = op1 * op2;

								int resultSize = (operandSize1 > operandSize2) ? operandSize1 : operandSize2;

								string strResult = ullToStr(result, resultSize);

								cout << strResult << endl;

								field->addValue(new FieldValue(instruction, index, strResult, fieldValue));
						}
					}

					else if(!ins.compare("div"))
					{
						cout << "not support div yet" << endl;
					}

					else if(!ins.compare("not") || !ins.compare("inc") ||
						!ins.compare("dec")
						)
					{
						if(index == 0){
							unsigned long long op1 = operands[index]->getValueInt(tOperandSize);

							//cout << hex <<"\t" << ins << " op1: " << op1 << " result: ";

							unsigned long long result = 0;

							if(!ins.compare("not"))
								result = ~op1;
							else if(!ins.compare("inc"))
								result = op1++;
							else if(!ins.compare("dec"))
								result = op1--;

							string strResult = ullToStr(result, tOperandSize);

							//cout << strResult << endl;

							field->addValue(new FieldValue(instruction, index, strResult, fieldValue));
						}
					}
					
					else if(!ins.compare("cmp"))
					{
						int operandSize2 = operands[(index+1)%2]->getSize();

						unsigned long long op1 = operands[index]->getValueInt(tOperandSize);
						unsigned long long op2 = operands[(index+1)%2]->getValueInt(operandSize2);

						//cout << hex <<"\t" << ins << " op1: " << op1 << " op2: " << op2 << endl;
					
						unsigned long long result = op1;

						string strResult = ullToStr(result, tOperandSize);

						//cout << strResult << endl;

						FieldValue* fv = new FieldValue(instruction, index, strResult, fieldValue);

						field->addValue(fv);	

					}
				}

			}
		}
	}

	cout << "Generation Field Transition Tree Finished." << endl;

	// print field transition tree
	for(itField = fields.begin(); itField != fields.end(); itField++){
		Field* field = *itField;

		vector<FieldValue*> fVal = field->getFieldValues();
		vector<FieldValue*>::iterator itFVal;

		if(field->getSize() > 1){
			cout << "field start: " << field->getStart();
			cout << " size: " << field->getSize()  << " fVal size: " << fVal.size() << endl;

			for(itFVal = fVal.begin(); itFVal != fVal.end(); itFVal++){

				(*itFVal)->print();

			}
		}
	}

	queryCount = 0;

	// get constraint value
	for(itField = fields.begin(); itField != fields.end(); itField++){
		Field* field = *itField;
		unsigned long long  start = field->getStart();
		unsigned long long size = field->getSize();
		string orig = field->getOrignalValue();

		
		cout << "[Get Constraint] field start: " << start << " size: " << size;

		vector<FieldValue*> fVal = field->getFieldValues();
		vector<FieldValue*>::iterator itFVal;

		cout << " value count: " << fVal.size() << endl;

		for(itFVal = fVal.begin(); itFVal != fVal.end(); itFVal++){


			if((*itFVal)->getInstruction()->getIns() == "cmp"){

				vector<unsigned long long> queryResult;
				vector<unsigned long long> temp;

				// need constraint solve
				//if( (*itFVal) != NULL){
				temp = (*itFVal)->queryConstraintCPP(0);
				queryResult.insert(queryResult.end(), temp.begin(), temp.end());


				temp = (*itFVal)->queryConstraintCPP(1);
				queryResult.insert(queryResult.end(), temp.begin(), temp.end());


				temp = (*itFVal)->queryConstraintCPP(2);
				queryResult.insert(queryResult.end(), temp.begin(), temp.end());
				//}

				// simply find new path
				//else {
				//	queryResult.push_back(op2);
				//	queryResult.push_back(op2+1);
				//	queryResult.push_back(op2-1);

				//}

				vector<unsigned long long>::iterator itquery;

				for(itquery = queryResult.begin(); itquery != queryResult.end(); itquery++){
					string constraint = ullToStr(*itquery, field->getSize());
					if(!field->isMarkerExist(constraint) && 
						!field->isConstraintExist(constraint)){
						//cout << "[constraints] " << constraint << " " << *itquery << endl;
						field->addConstraint(constraint);
					}

				}
			}
		}		
	}

	cout << dec << "[Constraint Solving] query count: " << queryCount << endl;
	cout << "Constraint Solving finished." << endl;

	queryCount = 0;

	// get interest value
	for(itField = fields.begin(); itField != fields.end(); itField++){
		Field* field = *itField;
		unsigned long long  start = field->getStart();
		unsigned long long size = field->getSize();
		string orig = field->getOrignalValue();

		
		cout << "[Get Interest] field start: " << start << " size: " << size;

		vector<FieldValue*> fVal = field->getFieldValues();
		vector<FieldValue*>::iterator itFVal;

		cout << " value count: " << fVal.size() << endl;

		for(itFVal = fVal.begin(); itFVal != fVal.end(); itFVal++){
			string ins = (*itFVal)->getInstruction()->getIns();

			if(ins == "cmp") continue;

			vector<unsigned long long> queryResult;
			vector<unsigned long long> temp;

			if(ins == "add" || ins == "mul" || ins == "imul" || ins == "shl"){
				temp = (*itFVal)->queryBoundaryCPP(SIO);
				queryResult.insert(queryResult.end(), temp.begin(), temp.end());

				temp = (*itFVal)->queryBoundaryCPP(UIO);
				queryResult.insert(queryResult.end(), temp.begin(), temp.end());
			}
			else if(ins == "sub"){
				queryResult = (*itFVal)->queryBoundaryCPP(UIU);
			}

			vector<unsigned long long>::iterator itquery;

			for(itquery = queryResult.begin(); itquery != queryResult.end(); itquery++){
				string interest = ullToStr(*itquery, field->getSize());
				if(!field->isMarkerExist(interest) && 
					!field->isConstraintExist(interest) &&
					!field->isInterestExist(interest)){
					//cout << "[Add Interest] " << interest << endl;
					field->addInterest(interest);
				}

			}
		}
		
	}

	cout << dec << "[Boundary Generation] query count: " << queryCount << endl;
	cout << "Boundary Generation finished." << endl;
	cout << "\n\n\n" << endl;


	int last = 0;

	for(itField = fields.begin(); itField != fields.end(); itField++){
		(*itField)->print();
	}

	//cout << "field count: " << fields.size() << endl;

	output.close();

	return 0;
		
}

