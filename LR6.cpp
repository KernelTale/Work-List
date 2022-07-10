#include "stdafx.h"
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>
#include <map>
#include <list>
#include <cmath>
using namespace std;
class IErrorLog {
public:
	virtual bool openLog(const char *filename) = 0;
	virtual bool closeLog() = 0;
	virtual bool writeError(const char *errorMessage) = 0;
	virtual ~IErrorLog() {};
};
class FileErrorLog {
private:
	ofstream logf;
public:
	virtual bool openLog(const char *filename) {
		logf.open(filename);
		return logf.is_open();
	}
	virtual bool closeLog() {
		logf.close();
		return logf.is_open();
	}
	virtual bool writeError(const char *errorMessage) {
		logf << errorMessage;
	}
	virtual ~FileErrorLog() {};
};
class MessageErrorLog {
public:
	virtual bool openLog(const char *filename) {
		return 0;
	}
	virtual bool closeLog() {
		return 0;
	}
	virtual bool writeError(const char *errorMessage) {
		cout << '\n' << errorMessage << '\n';
		return 1;
	}
	virtual ~MessageErrorLog() {};

};

class Calculation {
private:
		list <pair<string,double>> stack;
		map <string, double> variables;
		map <string, double> ::iterator it;
		//===============================================================
		// a bunch of methods
		friend class Command;
		void Define(string a, double num) {
			variables.insert(make_pair(a, num));
		}
		void Push(string a, MessageErrorLog log) {
			if (variables.find(a) != variables.end()) {
				pair <string, double> variable = make_pair(variables.find(a)->first, variables.find(a)->second);
				stack.push_back(variable);
			}
			else log.writeError("the variable doesn't exist yet");
		}
		void Pop(MessageErrorLog log) {
			if(stack.empty() != true)
			stack.pop_back();
			else log.writeError("the stack is empty already");
		}
		void Sqrt(MessageErrorLog log) {
			if (stack.empty() != true) {
				if ((stack.back()).second >= 0.0) {
					double a = sqrt((stack.back()).second);
					pair <string, double> variable = make_pair((stack.back()).first, a);
					stack.pop_back();
					stack.push_back(variable);
				}
				else log.writeError("the variable has negative value");
			}
			else log.writeError("the stack is empty");
		}
		void Plus(MessageErrorLog log) {
			if (stack.empty() != true) {
				list<pair<string, double>>::iterator it = stack.end();
				double a = (*it).second;
				advance(it, -1);
				double b = (*it).second;
				a = a + b;
				pair <string, double> variable = make_pair((stack.back()).first, a);
				stack.pop_back();
				stack.pop_back();
				stack.push_back(variable);
			} else log.writeError("the stack is empty");
		}
		void Minus(MessageErrorLog log) {
			if (stack.empty() != true) {
				list<pair<string, double>>::iterator it = stack.end();
				double a = (*it).second;
				advance(it, -1);
				double b = (*it).second;
				a = b - a;
				pair <string, double> variable = make_pair((stack.back()).first, a);
				stack.pop_back();
				stack.pop_back();
				stack.push_back(variable);
			} else log.writeError("the stack is empty");
		}
		void Multipy(MessageErrorLog log) {
			if (stack.empty() != true) {
			list<pair<string, double>>::iterator it = stack.end();
			double a = (*it).second;
			advance(it, -1);
			double b = (*it).second;
			a = a * b;
			pair <string, double> variable = make_pair((stack.back()).first, a);
			stack.pop_back();
			stack.pop_back();
			stack.push_back(variable);
		} else log.writeError("the stack is empty");
		}
		void Print(MessageErrorLog log) {
			cout << '\n' << (stack.back()).second << '\n';
		}
		void Divide(MessageErrorLog log) {
			if (stack.empty() != true) {
			list<pair<string, double>>::iterator it = stack.end();
			advance(it, -1);
			cout << (*it).second << '\n';
			double a = (*it).second;
			if (a != 0.0) {
				advance(it, -1);
				double b = (*it).second;
				a = b / a;
				pair <string, double> variable = make_pair((stack.back()).first, a);
				stack.pop_back();
				stack.pop_back();
				stack.push_back(variable);
			}
			else log.writeError("divide by null");
			} else log.writeError("the stack is empty");
		}

	//===============================================================
	// next bunch of methods

		/*WRITE error exceptions / command recognizer / some usefull stuff */ 
	//===============================================================
public:
	Calculation() {}
	~Calculation(){}
};

class Command {
private:
	vector <string> commlist = { "#", "PUSH", "push", "POP", "pop", "+", "-", "*", "/" , "SQRT", "PRINT", "DEFINE" };
	stringstream command;
	string shortcomm;
	vector <string> commstack;
	MessageErrorLog logg;
	string comComparison(string& comm) {
		for (int i = 0; i < comm.length(); i++) {
			if (comm[i] != '#')
				continue;
			else
				comm.erase(comm.begin() + i, comm.end());
		}
		return comm;
	}
	/*	1,2: PUSH
		3,4: POP
		5: +
		6: -
		7: *
		8: /
		9: SQRT
		10: PRINT
		11: DEFINE
	*/
	int whoComparison(string& comm) {
		for (int i = 1; i < commlist.size(); i++) {
			if (comm == commlist[i])
				return i;
			else if (comm == "stop" || comm == "STOP")
				return -1;
			else
				continue;
			}
		}
	void Calculus(Calculation& calc, int& wick) {
		for (int i = 0; i < commstack.size(); i++) {
			bool sizze = ((i + 2) < commstack.size());
			switch (whoComparison(commstack[i])) {
			case 1:
			case 2: 
				calc.Push(commstack[i + 1], logg); break;
			case 3:
			case 4: 
				calc.Pop(logg); break;
			case 5: calc.Plus(logg); break;
			case 6: calc.Minus(logg); break;
			case 7: calc.Multipy(logg); break;
			case 8: calc.Divide(logg); break;
			case 9: calc.Sqrt(logg); break;
			case 10: calc.Print(logg); break;
			case 11: if ((i + 2) < commstack.size()) { calc.Define(commstack[i + 1], atof(commstack[i + 2].c_str())); i += 2; }
					 else logg.writeError("the variable has to be defined as 'DEFINE variable_pos value_pos'"); break;
			case -1: wick = -1; break;
			}
		}
	}
public:
	Calculation ee;
	int stop;
	Command() {
		while (stop != -1) {
			stringstream command;
			getline(cin, shortcomm);
			command << shortcomm;
			while (!command.eof()) {
				command >> shortcomm;
				commstack.push_back(shortcomm);
			}
			Calculus(ee, stop);
		}
	}
	Command(ifstream& commfile) {
		while (!commfile.eof()) {
			shortcomm = "";
			getline(commfile, shortcomm);
			commstack.push_back(shortcomm);
		}
		//cleaning from #comments
		for (int i = 0; i < commstack.size(); i++) {
			comComparison(commstack[i]);
			command << '\n' << commstack[i];
		}
		commstack.clear();
		for (int i = 0; !command.eof(); i++) {
			command >> shortcomm;
			cout << shortcomm << '\n';
			commstack.push_back(shortcomm);
		}
		Calculus(ee, stop);
	}
	~Command(){}
};

int main()
{
	ifstream dio("d:\\feet.txt");
	Command jojo;
	
	system("pause");
    return 0;
}
