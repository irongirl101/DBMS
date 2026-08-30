CREATE DATABASE cve_management_system;
SHOW DATABASES;

USE cve_management_system;
SHOW TABLES;

CREATE TABLE VENDOR (
    Vendor_ID     INT PRIMARY KEY,
    Name          VARCHAR(100) NOT NULL
);
DESC VENDOR;

CREATE TABLE PRODUCT (
    Product_ID    INT PRIMARY KEY,
    Name          VARCHAR(100) NOT NULL,
    Ver           VARCHAR(20),
    Vendor_ID     INT NOT NULL,
    FOREIGN KEY (Vendor_ID) REFERENCES VENDOR(Vendor_ID)
);
DESC PRODUCT;

CREATE TABLE VULN_CLASS (
    Vuln_Class_ID INT PRIMARY KEY,
    Type          VARCHAR(50),
    CVSS          DECIMAL(3,1)
);
DESC VULN_CLASS;

CREATE TABLE CVE (
    CVE_ID        VARCHAR(20) PRIMARY KEY,
    CVSS          DECIMAL(3,1),
    Date          DATE,
    Description   TEXT,
    Type          VARCHAR(50),
    Vuln_Class_ID INT NOT NULL,
    FOREIGN KEY (Vuln_Class_ID) REFERENCES VULN_CLASS(Vuln_Class_ID)
);
DESC CVE;

CREATE TABLE PATCH (
    Patch_ID       INT PRIMARY KEY,
    Patch_Fix_Date DATE,
    Fix_Desc       TEXT,
    CVE_ID         VARCHAR(20) UNIQUE,
    FOREIGN KEY (CVE_ID) REFERENCES CVE(CVE_ID)
);
DESC PATCH;

CREATE TABLE AFFECTED (
    Product_ID    INT,
    CVE_ID        VARCHAR(20),
    PRIMARY KEY (Product_ID, CVE_ID),
    FOREIGN KEY (Product_ID) REFERENCES PRODUCT(Product_ID),
    FOREIGN KEY (CVE_ID) REFERENCES CVE(CVE_ID)
);
DESC AFFECTED;

SHOW TABLES;