-- MySQL dump 10.10
--
-- Host: localhost    Database: btb
-- ------------------------------------------------------
-- Server version	5.0.15-Debian_1-log
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO,ANSI' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table "clients"
--

DROP TABLE IF EXISTS "clients";
CREATE TABLE "clients" (
  "id" int(11) NOT NULL auto_increment,
  "login" datetime default NULL,
  "last_ping" datetime default NULL,
  "username" varchar(100) default NULL,
  "capabilities" int(64) default NULL,
  "sysname" varchar(100) default NULL,
  "releases" varchar(100) default NULL,
  "machine" varchar(100) default NULL,
  "cracked" int(20) default NULL,
  "clientid" int(20) default NULL,
  "jobid" int(12) default NULL,
  PRIMARY KEY  ("id")
);

--
-- Table structure for table "jobs"
--

DROP TABLE IF EXISTS "jobs";
CREATE TABLE "jobs" (
  "id" int(11) NOT NULL auto_increment,
  "cipher" int(11) default NULL,
  "owner" varchar(100) default NULL,
  "comment" varchar(255) default NULL,
  "status" enum('active','paused','finished','aborted') default NULL,
  "datestart" datetime default NULL,
  "priority" int(11) default NULL,
  "interval_size" int(64) default NULL,
  "crack_method" int(11) default NULL,
  "curprio" int(11) default '0',
  PRIMARY KEY  ("id")
);

--
-- Table structure for table "passwords"
--

DROP TABLE IF EXISTS "passwords";
CREATE TABLE "passwords" (
  "id" int(11) NOT NULL auto_increment,
  "username" varchar(255) default NULL,
  "hash" varchar(255) default NULL,
  "salt" varchar(10) default NULL,
  "cleartext" varchar(255) default NULL,
  "jobid" int(11) default NULL,
  PRIMARY KEY  ("id")
);

--
-- Table structure for table "spaces"
--

DROP TABLE IF EXISTS "spaces";
CREATE TABLE "spaces" (
  "id" int(11) NOT NULL auto_increment,
  "start" int(64) default NULL,
  "end" int(64) default NULL,
  "status" enum('done','doing','aborted') default NULL,
  "passwordid" int(11) default NULL,
  "clientid" int(11) default NULL,
  PRIMARY KEY  ("id")
);
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

