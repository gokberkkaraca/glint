import sqlite3

conn = sqlite3.connect('lint_results.db')
db = conn.cursor()

db.execute('DROP TABLE IF EXISTS results')
db.execute('DROP TABLE IF EXISTS certificates')
db.execute('DROP TABLE IF EXISTS lints')

db.execute('''CREATE TABLE certificates(
    certificate_id text primary key not null, 
    certificate_issuer text,
    certificate_subject text, 
    certificate_date text)''')

db.execute('''CREATE TABLE lints(
    lint_name text primary key not null, 
    lint_source text, 
    lint_effective_date text)''')

db.execute('''CREATE TABLE results(
    certificate_id text not null, 
    lint_name text not null, 
    result text,
    primary key (certificate_id, lint_name),
    foreign key (certificate_id) references certificates,
    foreign key (lint_name) references lints)''')
