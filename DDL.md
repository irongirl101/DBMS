### Commands 

Create Database: 
`create database cve;`

Use Database: 
`use cve`

Create tables: 
`
create table VENDOR(Vendor_ID INT PRIMARY_KEY, Name Varchar(100));

create table product(ID INT PRIMARY KEY,Product_Name varchar(100), Version varchar(30));

create table CVE(CVE_ID VARCHAR(30) PRIMARY KEY, CVSS DECIMAL(3,1), `Date` DATE, `Desc` TEXT, `Type` Varchar(50));
`



Relationship Tables: 
`create table product_vendor(Product_ID INT, Vendor_ID INT, PRIMARY KEY (Product_ID, Vendor_ID), FOREIGN KEY (Product_ID) REFERENCES PRODUCT(ID), FOREIGN KEY (Vendor_ID) REFERENCES Vendor(Vendor_ID));`

create table vuln_class(vuln_class_id int PRIMARY KEY, CVE_ID Varchar(30) UNIQUE, Patch_Fix_Datc Date, Fix_desc Text, FOREIGN KEY (CVE_ID) REFERENCES CVE(CVE_ID));

create table affected(Product_ID INT, CVE_ID Varchar(30), PRIMARY KEY (Product_ID, CVE_ID),
    ->     FOREIGN KEY (Product_ID) REFERENCES PRODUCT(ID),
    ->     FOREIGN KEY (CVE_ID) REFERENCES CVE(CVE_ID)
    -> );

`


