## @mainpage
# sqltool analyzes SQL scripts or logs.
# It can group statements by transaction and determine the ratio of writing statement
# as well as transactions containing at least one write.
# 
# @author Victor Hahn, Flexoptix GmbH
# @author victor.hahn@flexoptix.net
# @version 0.1
## @copyright
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING file for more details.


# FIRST PART OF MAIN

# load always needed libraries
import argparse
import re
import sys
import math

##
# Parse command line arguments, then determine which additional libraries to import
# also provide command line help
parser = argparse.ArgumentParser(description="A tool to determine the write ratio of SQL script, group SQL queries by transaction, and other purposes.", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("action", choices=["writeratio", "split"], help="Select what to do. writeratio calculates the percentage of writes in the log. split writes each transaction to its own file.")
parser.add_argument("--base", "-b", default="transaction", choices=["transaction", "statement"], help="Whether to use whole transactions or single statements as base blocks of information, where applicable.")
parser.add_argument("--autocommit", "-c", default="yes", choices=["yes","no"], help="Specify whether this script is supposed to run in autocommit mode")
parser.add_argument("--preformat", "-f", default="none", choices=["none","gql"],help="Preformat the input file. \"gpl\" expects a MySQL General Query Log.")
parser.add_argument("--parsemode", "-p", default="quick", choices=["quick","slow"],help="Switch between quick'n'dirty and slow'n'correct SQL parsing. Possible correct, that is.")
parser.add_argument("--inputfile", "-i", default="-", help="File with input data. \"-\" means stdin.")
parser.add_argument("--output", "-o", help="Base name for output file. Only needed for action split.")
args = parser.parse_args()

# conditional imports
if args.parsemode == "slow": import sqlparse

# set global/static stuff according to arguments
if args.parsemode == "slow":
  sqlwrapper.split = staticmethod(sqlwrapper.sqlsplit)
  sqlwrapper.parsetype = staticmethod(sqlwrapper.sqlparsetype)

# first part of main ends here






##
# Reads data from a text file.
# Provides for a callback after each line read.
class fileparser:

	##
	# @param inputfile File handler to read from. Default is standard input.
	# @param preformat If the input file is not a plain SQL script, specify its type.
	# So far, only MySQL General Query Logs ("gql") are supported besides plain SQL.
	# @param linecallback Reference to a function which shall be call after each line read.
	# This function must accept exactly one line of text as parameter.
	def __init__(self, inputfile=sys.stdin, preformat=False, linecallback = False):
		self.inputfile = inputfile
		self.preformat = preformat
		self.linecallback = linecallback

	## Documentation for a method.
	#  @param self The object pointer.
	def readline(self):
		processline(self.inputfile.readline())
	
	def readall(self):
		for line in self.inputfile:
			self.processline(line)

	def processline(self, line):
		if self.preformat=="gql":
			pattern = re.compile(" Query\t")
			parts = pattern.split(line) 
			if len(parts)>1:
				line = parts[1]
			else:
				return
		if self.linecallback:
			self.linecallback(line)
			


##
# Provides static methods to split SQL statements and get their types.
# Can be configured to use the sqlparse library or a faster (and probably more error prone)
# string operation based solution as backend.
class sqlwrapper:

	##
	# Split a line of SQL code into a list of individual statements.
	# If you've chosen the fast and dirty implementation, this basically splits the line by semicolons.
  @staticmethod
  def sqlsplit(input):
    splitted = sqlparse.split(input)
    return splitted

	##
	# Extract the type of SQL instruction from a single SQL statement.
	# If you've chosen the fast and dirty implementation, this basically gives you
	# the statement's first word.
  @staticmethod
  def sqlparsetype(input):
    type = sqlparse.parse(input)[0].get_type()
    return type

	##
	# Fast and dirty implementation of the sqlsplit method.
  @staticmethod
  def manualsplit(input):
    # split at semicolon; then remove leading whitespace
    splittedRaw = input.split(";")
    splitted = []
    for statement in splittedRaw:
      statement = statement.lstrip()
      # discard empty "statements" (e.g. just a semicolon)
      if statement != "": splitted.append(statement)
    return splitted

  ##
  # Fast and dirty implementation of the sqlparsetype method.
  @staticmethod
  def manualparsetype(input):
    splitted = input.split(" ");
    return splitted[0].rstrip()
  
  # static member initialization
  # default to sqlparse backend
  split = manualsplit
  parsetype = manualparsetype




##
# Groups SQL statements into transactions for further analyzation.
class TransactionSplitter:

	##
	# @param autocommit Whether the DBMS this log comes from ran in autocommit mode.
	# In autocommit mode, statements which are not surrounded by a BEGIN/COMMIT block
	# are committed instantaneously.
	# Otherwise (in standard SQL code), a statement automatically opens a new transaction
	# which will only be committed when explicitly told so.
	# @param transactioncallback Shall we call a function after each transaction we identified?
	# If so, this parameter must be set to a function or closure to be called.
	# @param savetransaction Shall we keep a list of all transactions in RAM?
	# If not, each transaction will be discarded immediately after it has been completely identified
	# and the transaction callback was performed, if applicable.
	# @param stats Whether to store transaction sized for statistics.
	def __init__(self, autocommit=True, transactioncallback=False, savetransaction=False, stats=False):
		self.autocommit = autocommit
		self.savetransaction = savetransaction
		self.transactioncallback = transactioncallback
		self.stats = stats

		## @property transactions
		# will contain a list of all transactions
		# each transaction is itself a list of statements
		# each statement is a string		
		self.transactions = []
		
		
		## @property transactionsizes
		# Will contain a list of transaction sizes, i.e. number of statements per transaction
		self.transactionsizes = []

		## @property currentTransaction
		## @private The transaction currently being parsed.
		# Will be added to transactions when parsing is finished.
		self.currentTransaction = []

		## @property manualTransaction
		## @private will be set to True if there is an explicit BEGIN or START in autocommit mode
		self.manualTransaction = False

		## @property largest
		# The largest number of statements encountered in a transaction.
		self.largest = False

		## @property smallest
		# The smallest number of statements encountered in a transaction.
		self.smallest = False
		
		## @property mean
		# Mean number of statements per transaction.
		# calcstats() must be called to calculate this value.
		self.mean = False

		## @property std
		# Standard deviation from the mean number of statements per transaction.
		# calcstats() must be called to calculate this value.
		self.std = False
		

	##
	# Analyze a single line of SQL code.
  # A line may contain multiple statements.
	# This method can be used as a callback for a fileparser object.
	# @param line A new line of code to be analyzed.
	def executeline(self, line):
		statements = sqlwrapper.split(line)
		for statement in statements:
			self.handleStatement(statement)

	##
	# Analyze a single SQL statement
	# @param statement A new statement to be analyzed.
	def handleStatement(self, statement):
		type = sqlwrapper.parsetype(statement)
		if type == "BEGIN" or type == "START":
			self.manualTransaction = True
		elif type == "COMMIT" or type == "ROLLBACK":
			self.finalizeTransaction()
		else:
			self.currentTransaction.append(statement)
			if self.autocommit and not self.manualTransaction:
				self.finalizeTransaction()

	##
	# Private method which will be called after a complete transaction has been identified.
	def finalizeTransaction(self):
		# Save processed transaction to array if this feature is enabled:
		if self.savetransaction:
			self.transactions.append(self.currentTransaction)
			
		# Perform per-transaction callback if this feature is enabled:
		if self.transactioncallback:
			self.transactioncallback(self.currentTransaction)
		
		# Save transaction size for statistics if this feature is enabled:
		if self.stats == True:
			if len(self.currentTransaction) > 0:
				self.transactionsizes.append(len(self.currentTransaction))
			
		# clean up an discard current transaction
		self.currentTransaction = []
		self.manualTransaction = False

	##
	# Update object's statistics, calculate mean transaction size and standard deviation.
	def calcstats(self):
		# Did we even collect data?
		if len(self.transactionsizes) == 0: return False, False
		
		# calculate mean and determine largest/smallest transaction
		sum = 0
		self.largest = False
		self.smallest = False
		for value in self.transactionsizes:
			sum += value
			if not self.largest or value > self.largest: self.largest = value
			if not self.smallest or value < self.smallest: self.smallest = value
		self.mean = float(sum) / len(self.transactionsizes)
		
		# calculate standard deviation
		sum = 0
		for value in self.transactionsizes:
			summand = (self.mean-value)**2
			sum += summand
		self.std = math.sqrt(sum / ( len(self.transactionsizes) - 1))
		
		


##
# Analyzes transactions for write operations.
# Stores the number of transactions containing at least one write.
class WriteCounter:
	##
	# @param transactions A list of transactions to analyze.
	# Expected to be a list of transactions where each transaction is a list of statements.
	# Incidentally, this is exactly what the output a TransactionSplitter looks like.
	def __init__(self, transactions = []):
	
		## @property transactions
		# Store of all transactions to analyze.
		# Note that it is not necessary to use this store; transactions can also be analyzed
		# one by one (e.g. by using analyzeTransaction as a callback from a TransactionSplitter)
		self.transactions = transactions
		
		## @property total
		# Total number of transactions analyzed.
		# Is 0 on construction as transaction will be counted as they are analyzed.
		self.total = 0
		
		## @property withwrite
		# Result will be stored here: Number of transactions containing writes.
		self.withwrite = 0
    
	##
	# Analyzes all transactions currently stored in this object.
	# Note that calling this two times might well double your result.
	def analyzeAll(self):
		for transaction in self.transactions:
			analyzeTransaction(transaction)

	##
	# Analyze a single transaction given as parameter.
	# Note that calling this two times on the same transaction might well double your result.
	# @param transaction Transaction to be analyzed as a list of statements
	def analyzeTransaction(self, transaction):
		write = False
		for statement in transaction:
			write = self.analyzeStatement(statement)
			if write: break
		self.total = self.total + 1
		if write:
			self.withwrite = self.withwrite + 1
		
	##
	# Analyze a single line of raw SQL code, possibly containing multiple statements.
	# This (only) makes sense if you want to determine a statement write ratio,
	# not a transaction based one.	
	# @param line Line of raw SQL code to be analyzed.
	def analyzeLine(self, line):
		statements = sqlwrapper.split(line)
		for statement in statements:
			self.total += 1
			if self.analyzeStatement(statement): self.withwrite += 1
	
	##
	# Analyze a single SQL statement.
	# @param statement Single statement to be analyzed.
	# @return True if this statement is a write, false otherwise.
	def analyzeStatement(self, statement):
		type = sqlwrapper.parsetype(statement)
		if type == "UPDATE" or type == "INSERT" or type == "DELETE":
			return True




# HELPER FUNCTIONS
def makeFileparser():
  p = fileparser(preformat=args.preformat)
  if args.inputfile != "-":
    file = open(args.inputfile)
    p.inputfile = file
  return p
    
def makeTransactionSplitter():
  a = TransactionSplitter(stats=True)
  if args.autocommit == "no":
    a.autocommit = False
  return a




# MAIN
def main():
	if args.action == "writeratio":
		fileparser = makeFileparser()
		transactionsplitter = makeTransactionSplitter()
		writecounter = WriteCounter()
	  
		if args.base == "transaction":
			fileparser.linecallback = transactionsplitter.executeline
			transactionsplitter.transactioncallback = writecounter.analyzeTransaction
			fileparser.readall()
			transactionsplitter.calcstats()
			ratio = float(writecounter.withwrite*100)/writecounter.total
			print "Total number of transactions: " + str(writecounter.total)
			print "Transactions containing writes: " + str(writecounter.withwrite)
			print "Ratio: " + "{:.2f}".format(ratio) + "%"
			print "Mean transaction size: " + "{:.2f}".format(transactionsplitter.mean) + " (s = " + "{:.2f}".format(transactionsplitter.std) + ", smallest " + str(transactionsplitter.smallest) + ", largest " + str(transactionsplitter.largest) + ")"
			
		elif args.base == "statement":
			fileparser.linecallback = writecounter.analyzeLine
			fileparser.readall()
			ratio = float(writecounter.withwrite*100)/writecounter.total
			print "Total number of statements: " + str(writecounter.total)
			print "Write statements: " + str(writecounter.withwrite)
			print "Ratio: " + "{:.2f}".format(ratio) + "%"
		else: return False
	  
	
	
	
	
	
	if args.action == "split":
		if args.base == "statement":
			print("Sorry, split is not implemented for --base statement.")
			sys.exit()
		if not args.output:
			print("Cannot split file if output file not specified.")
			sys.exit()
	    
		p = makeFileparser()
		a = makeTransactionSplitter()
		p.linecallback = a.executeline
		a.savetransaction=True
		p.readall()
		counter = 1
		for transaction in a.transactions:
			file = open(args.output + str(counter), "w")
			for line in transaction:
				file.write(line)
			counter += 1



if __name__=="__main__":
   main()
