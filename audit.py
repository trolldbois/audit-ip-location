#!/usr/bin/python
import argparse
import csv
import datetime
import fileinput
import logging
import os
import sqlite3
import sys
import socket
import urllib
import time

import bsddb



log=logging.getLogger('audit')

GEOIP_CITIES='geoip/berkelydb/hip_ip4_city_lat_lng.db'
GEOIP_COUNTRIES='geoip/berkelydb/hip_ip4_country.db'

from conf import GW

# Used to find PRIVATE ip range
def bin2int(s):
    return sum(int(n)*2**i for i, n in zip(range(len(s)), s[::-1]))


from sqlalchemy import Table, Column, Integer, Float, String, Sequence, MetaData, PrimaryKeyConstraint, ForeignKey, UniqueConstraint, DateTime
from sqlalchemy.types import TIMESTAMP
from sqlalchemy.orm import relationship, validates
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session,sessionmaker
from sqlalchemy.sql.expression import desc

Base = declarative_base()

class Logins(Base):
  '''
    'CREATE TABLE logins (id INTEGER, date TEXT, time TEXT, user '\
    'TEXT, src TEXT, server TEXT, ts TIMESTAMP, CONSTRAINT logins '\
    'PRIMARY KEY(id,date,server) )')
  '''
  __tablename__="logins"
  
  tid=Column('id',Integer)
  date=Column('date',String(8))
  tim=Column('time',String(8))
  user=Column('user',String(16))
  src=Column('src',String(14))
  server=Column('server',String(14))
  ts=Column('ts',TIMESTAMP())
  
  __table_args__= (PrimaryKeyConstraint( tid,date,server),{}) 
  
  def __eq__(self,other):
    if other is None or not hasattr(other,'tid') or not hasattr(other,'date'):
      return False
    if self.tid == other.tid and self.date == other.date and \
        self.user == other.user and self.server == other.server and \
        self.src == other.src:
      return True
    return False
  def __ne__(self,other):
    return not self.__eq__(other)
  def __hash__(self):
    return hash(self.tid)
  def __repr__(self):
    return '<Logins %s %s %s %s %s %s>'%(self.tid, self.date, self.tim, self.src, self.user, self.ts)  

class IP2ASN(Base):
    '''
    'CREATE TABLE ip2asn (ip TEXT, asn INTEGER, city TEXT, lat '\
    'FLOAT, long FLOAT, CONSTRAINT ip2asn UNIQUE(ip) )')
    '''
    __tablename__="ip2asn"

    ip=Column('ip',String(14))
    asn=Column('asn',Integer)
    city=Column('city',String(256))
    lat=Column('lat',Float())
    lon=Column('long',Float())

    __table_args__= (PrimaryKeyConstraint(ip),{}) 

    @validates('city')
    def validate_city(self, key, city):
        return urllib.unquote(city.decode('iso-8859-15'))
  
    def __eq__(self,other):
        if other is None or not hasattr(other,'ip'):
            return False
        if self.ip == other.ip:
            return True
        return False
    def __ne__(self,other):
        return not self.__eq__(other)
    def __hash__(self):
        return hash(self.ip)
    def __repr__(self):
        c =self.city 
        if c is not None: # __repr__ is str in python2
            c='<{}>'.format(repr(self.city))
        return '<IP2ASN %s %s %s %s %s>'%(self.ip, self.asn, c, self.lat, self.lon)  

class ASN(Base):
  '''
    'CREATE TABLE asn (asn INTEGER, prefix TEXT, cc TEXT, '\
    'CONSTRAINT asn UNIQUE(prefix) )')
  '''
  __tablename__="asn"
  
  asn=Column('asn',Integer)
  prefix=Column('prefix',String(17))
  cc=Column('cc',String(4))
  
  __table_args__= (PrimaryKeyConstraint(asn,prefix),{}) 
  
  def __eq__(self,other):
    if other is None or not hasattr(other,'asn'):
      return False
    if self.asn == other.asn and self.prefix == other.prefix:
      return True
    return False
  def __ne__(self,other):
    return not self.__eq__(other)
  def __hash__(self):
    return hash(self.ip)
  def __repr__(self):
    return '<ASN %s %s %s>'%(self.asn, self.prefix, self.cc)  


'''Database creation and accessors'''
class DB:
    _conn=None
    _cursor=None
    def __init__(self, dbname):
        self.engine = create_engine('sqlite:///%s'%(dbname),echo=False)
        self.session = scoped_session(sessionmaker(autocommit=False,
                                              autoflush=False,
                                              bind=self.engine))
        #create table if necessary
        Base.metadata.create_all(self.engine)
        #old FIXME
        #self.conn
        
    def clean(self):
        if self._conn is not None:
            self._conn.close()
            self._conn=None
        _conn = sqlite3.connect('alllogins.db')
        for t in ['ip2asn','user2asn']:
            try:
                _conn.cursor().execute('DROP TABLE %s'%(t))
            except sqlite3.OperationalError,e:
                print 'error on drop table',t,e
        _conn.commit()
            
    @property
    def conn(self):
        if self._conn is None:
            self._conn = sqlite3.connect('alllogins.db')
        try:
            if self.cursor.execute('SELECT COUNT(date) FROM logins'):
                pass
        except sqlite3.OperationalError,e:
            # Create table
            # we need DATE, TIMESTAMP, not TEXT field.
            self.cursor.execute(
                'CREATE TABLE logins (id INTEGER, date TEXT, time TEXT, user '\
                'TEXT, src TEXT, server TEXT, ts TIMESTAMP, CONSTRAINT logins '\
                'PRIMARY KEY(id,date,server) )')
        # asn
        try:
            if self.cursor.execute('SELECT COUNT(asn) FROM asn'):
                pass
        except sqlite3.OperationalError,e:
            # Create table
            self.cursor.execute(
                'CREATE TABLE asn (asn INTEGER, prefix TEXT, cc TEXT, '\
                'CONSTRAINT asn UNIQUE(prefix) )')
        # ip2asn
        try:
            if self.cursor.execute('SELECT COUNT(ip) FROM ip2asn'):
                pass
        except sqlite3.OperationalError,e:
            # Create table
            self.cursor.execute(
                'CREATE TABLE ip2asn (ip TEXT, asn INTEGER, city TEXT, lat '\
                'FLOAT, long FLOAT, CONSTRAINT ip2asn UNIQUE(ip) )')
        # user2asn will be a union request.
        try:
            if self.cursor.execute('SELECT COUNT(userid) FROM user2asn'):
                pass
        except sqlite3.OperationalError,e:
            # Create table
            self.cursor.execute(
                'CREATE TABLE user2asn (userid TEXT, asn INTEGER, CONSTRAINT '\
                'user2asn UNIQUE(userid,asn) )')

    @property
    def cursor(self):
        if self._cursor is None:
            self._cursor = self._conn.cursor()
        return self._cursor

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()
        self._conn = None
                

''' Database queries '''
class Worker(DB):
    
    # TABLE logins
    def addLogin(self, id, d,t,user,src,dst,ts ):
        try:
            self.cursor.execute(
                'INSERT OR IGNORE INTO logins VALUES (?,?,?,?,?,?,?)', 
                    (id, d,t,user,src,dst,ts) )
        except sqlite3.IntegrityError,e:
            log.error('addLogin: %s,%s'%(user,src))

    def addMultipleLogin(self, logins):
        try:
            self.cursor.executemany(
                'INSERT OR IGNORE INTO logins VALUES (?,?,?,?,?,?,?)', 
                    logins )
        except sqlite3.IntegrityError,e:
            log.error('addMultipleLogins: %s'%(logins))

    def getUniqueUsers(self):
        self.cursor.execute('SELECT DISTINCT user FROM logins')
        return self.cursor.fetchall()

    def countUsers(self):
        self.cursor.execute('SELECT COUNT(DISTINCT user) FROM logins')
        return self.cursor.fetchone()[0]

    def countIPSources(self):
        self.cursor.execute('SELECT COUNT(DISTINCT src) FROM logins')
        return self.cursor.fetchone()[0]
    
    def getLogins(self):
        self.cursor.execute('SELECT id,date,time,user,src,server,ts FROM logins')
        return self.cursor.fetchall()

    # TABLE ASN
    def addASN(self, asn ):
        try:
            self.cursor.execute('INSERT OR IGNORE INTO asn VALUES (?,?,?)', 
                (asn.asn, asn.prefix, asn.cc) )
        except sqlite3.IntegrityError,e:
            log.error('addASN: %s'%(asn))

    def getASNCache(self):
        self.cursor.execute('SELECT asn,prefix,cc FROM asn GROUP BY asn,cc')
        return [(asn, prefix, cc) for asn, prefix, cc in self.cursor.fetchall()]

    def countUniqueASN(self):
        self.cursor.execute('SELECT COUNT(DISTINCT asn) FROM ip2asn')
        return self.cursor.fetchone()[0]

    # TABLE IP2ASN
    def addIP2ASN(self, ip, asn, city, lat, lon ):
        try:
            if city is not None:
                city = urllib.unquote(city.decode('iso-8859-15'))
            self.cursor.execute(
                'INSERT OR IGNORE INTO ip2asn VALUES (?,?,?,?,?)', 
                    (ip, asn.asn, city, lat, lon) )
        except sqlite3.IntegrityError,e:
            log.error('addIP2ASN: %s:%s'%(ip,asn))

    def getIP2ASN(self):
        self.cursor.execute('SELECT ip,asn,city,lat,long FROM ip2asn')
        # ip, asn, city, lat, lon 
        return self.cursor.fetchall()

    # TABLE user2ASN
    def addMultipleUser2ASN(self, user2asnList ):
        try:
            self.cursor.executemany(
                'INSERT OR IGNORE INTO user2asn VALUES (?,?)', 
                    user2asnList )
        except sqlite3.IntegrityError,e:
            log.error('addMultipleUser2ASN: %s'%(
                ','.join([str(x) for x in user2asnList])))
        return self.cursor.rowcount

    def countUniqueCountries(self):
        self.cursor.execute('SELECT COUNT(DISTINCT cc) FROM user2asn')
        return self.cursor.fetchone()[0]
    
    # JOINED TABLE requests
    def getUserLoginLocation(self,username):
        self.cursor.execute(
            'SELECT ts,user,src,asn,city,lat,long FROM logins,ip2asn WHERE '\
                'src == ip2asn.ip AND user = ? ORDER BY ts ASC', (username,))
        # ts,user,src,asn,city,lat,lon 
        return self.cursor.fetchall()

    def getCountries(self):
        self.cursor.execute(
            'SELECT user,asn.asn,asn.cc FROM logins,ip2asn,asn '\
            'WHERE logins.src = ip2asn.ip AND ip2asn.asn = asn.asn '\
            'ORDER BY logins.user,asn.cc')
        # user,asn,cc
        return self.cursor.fetchall()

    def getFullLogin(self):
        self.cursor.execute(
            'SELECT date,time,user,src,asn.asn,asn.cc FROM logins,ip2asn,asn '\
            'WHERE logins.src = ip2asn.ip AND ip2asn.asn = asn.asn '\
            'ORDER BY logins.user,asn.cc')
        # date,time,user,src,asn,cc 
        return self.cursor.fetchall()


'''Fix stuff in DB'''
class FixWorker(Worker):

    def fixLoginsTS(self):
        logins = self.session.query(Logins).filter(Logins.ts == None)
        # calculate ts
        cnt=0
        for login in self.session.query(Logins).filter(Logins.ts == None):
            ts=datetime.datetime.strptime("%s %s"%(login.date,login.tim),"%d%b%Y %H:%M:%S")
            login.ts=ts
            cnt+=1
            
        self.session.commit()
        log.info('[+] Logins Timestamp fix: %d fix'%(cnt))
        return cnt
    
    def fixASN(self):
        # save all ASN for GEOIP_CITIES IP
        ip2city=bsddb.btopen(GEOIP_CITIES)
        cymru_client = ip2asn()
        # get all known geoip sorted
        allips=set([int(x) for x in ip2city.keys()])
        allips.sort()
        asns=[x for x in self.session.query(ASN)]
        # avoid resolved ones.
        # TODO: save all ASN for logins src ip
        #for ip in 
    
    def getASNByPrefix(self,ipObj):
        import IPy
        asns=[x for x in self.session.query(ASN).filter(ASN.asn == ipObj.asn)]
        ip=IPy.IP(ipObj.ip)
        for asn in asns:
            if ip in IPy.IP(asn.prefix):
                return asn
    
    def fixIP2ASN(self):
        ''' get null-cities IP and fix them'''
        import IPy
        from cymru.ip2asn.dns import DNSClient as ip2asn
        ip2city=bsddb.btopen(GEOIP_CITIES)
        cymru_client = ip2asn()
        # get all known geoip sorted
        allips=[int(x) for x in ip2city.keys()]
        allips.sort()
        # get all missing ip2asn
        ips=[(IPy.IP(ipObj.ip).int(),ipObj) for ipObj in self.session.query(IP2ASN).filter(IP2ASN.city == None)]
        ips.sort()
        # go through all geoip, to find closest geoip from ipObj
        # then go to next ipObj
        misses=0
        fixes=0
        try:
            ind_geoip=0
            #last_geoip=allips[ind_geoip]
            ip_iter=iter(ips)
            for current,ipObj in ip_iter:
                # find the ASN and the prefix that contains IP
                asn=self.getASNByPrefix(ipObj)
                prefix=IPy.IP(asn.prefix)
                # find head
                while ind_geoip < len(allips) and (allips[ind_geoip]<=current):
                    ind_geoip+=1
                # ignore IndexError
                prefix_geoip=IPy.IP(allips[ind_geoip-1])
                if prefix_geoip not in prefix:
                    log.debug(' %s cymru_prefix %s !contains geoip %s %s'%
                              (ipObj.ip,prefix,prefix_geoip, IPy.IP(allips[ind_geoip])))
                    misses+=1
                    continue
                # fix the ip2asn entry
                city,lat,lon = ip2city[str(prefix_geoip.int())].split(' ')
                ipObj.city=city
                ipObj.lat=lat
                ipObj.lon=lon
                log.debug('FIXED %s'%(ipObj))
                fixes+=1
        except StopIteration,e:
            pass
        except IndexError,e:
            pass
        self.session.commit()
        log.info('[+] IP2ASN geoip location FIXED:%d MISSES:%d'%(fixes,misses))

''' Analysis and controllers'''
class AnalysisWorker(Worker):
    checks=None
    cache=None
    ip2city=None

    def cacheIPstoASN(self):
        import IPy
        from cymru.ip2asn.dns import DNSClient as ip2asn
        self.ip2city=bsddb.btopen(GEOIP_CITIES)
        cymru_client = ip2asn()
        print '[+] cacheIPstoASN get all logins'
        ips=set()
        # DEBUG
        for id,date,time,user,src,server,ts in self.getLogins():
            if src not in self.cache:
                ips.add(src)
        if len(ips) == 0:
            print '[+] 0 new src ips'
            return 0
        print '[+] cacheIPstoASN resolvemany (%d) user src ips'%(len(ips))
        # check results
        cnt=0
        # create a ASN prefix to ip2city IPs cache
        allips=[int(x) for x in ip2city.keys()]
        allips.sort()
        if False:
            print '[+] geoIP create a ASN prefix to ip2city IPs cache'
            prefix2cityIP=dict([(IPy.IP(prefix),[]) 
                                for asn,prefix,cc in self.getASNCache()])
            print '[+] geoIP cache %d togo'%(len(allips))
            allipsdone=0
            for ip_int in allips:
                ip = IPy.IP(int(ip_int))
                for k in prefix2cityIP.keys():
                    if ip in k:
                        prefix2cityIP[k].append(ip)
                        break
                allipsdone+=1
                print '[+] geoIP cache %d togo'%(len(allips)-allipsdone)
            print '[+] geoIP cache has been created'
        #
        # use it
        for ip,asn in zip(ips, cymru_client.lookupmany(ips,qType='IP')):
            done = False
            if asn.asn is None:
                continue
            self.addASN(asn) 
            #print ip, asn
            # check for PRIVATe prefix before
            ip_ip = IPy.IP(ip)
            if ip_ip.iptype() == 'PRIVATE':
                bits = ip_ip.strBin()
                for i in xrange(len(bits), 0, -1):
                    if bits[:i] in IPy.IPv4ranges:
                        prefix=IPy.IP(bin2int(bits[:i]))
                        self.addIP2ASN(ip, asn, 'BBD INTERNAL',None,None)
                        done=True
                        break
                if not done:
                    raise KeyError('%s should be private'%(ip))
                continue
            elif asn.prefix is None:
                raise KeyError('why is asn prefix null ? ip:%s asn:%s'%(ip,asn))
            # get the city from the IP prefix
            prefix = IPy.IP(asn.prefix)
            try:
                city,lat,lon = self.ip2city[str(prefix.int())].split(' ')
                print city,lat,lon
                self.addIP2ASN(ip, asn, city, lat, lon)
            except KeyError,e:
                #take the closest value in prefix
                ind=min(range(len(allips)), 
                        key=lambda i: abs(allips[i]-ip_ip.int()))
                prefix_2 = IPy.IP(allips[ind])
                
                #
                ##citiesIPlst = prefix2cityIP[prefix]
                # search for real match
                ##ind=min(range(len(citiesIPlst)), 
                ##        key=lambda i: abs(int(citiesIPlst[i])-ip_ip.int()))                
                ##prefix_2 = IPy.IP(int(citiesIPlst[ind]))
                
                # check if ip if really in asn.prefix
                # and that prefix_2 is really in asn.prefix
                if ip_ip not in prefix:
                    log.error('ip: %s not in prefix: %s'%(ip_ip,prefix))
                    self.addIP2ASN(ip, asn, None,None,None)
                elif prefix_2 not in prefix:
                    log.error('geoip prefix: %s not in prefix: %s'%
                              (prefix_2,prefix))
                    self.addIP2ASN(ip, asn, None,None,None)
                else:
                    city,lat,lon = self.ip2city[str(prefix_2.int())].split(' ')
                    print city,lat,lon,"(approx ip:%s to geoip:%s on "\
                          "prefix:%s)"%(ip,prefix_2,prefix)
                    self.addIP2ASN(ip, asn, city, lat, lon)
            cnt+=1
            if (cnt%10)==0:
                self.commit()
        print '[+] cacheIPstoASN end %d resolves'%(cnt)
        return cnt
    
    def resolve(self):
        userdict=dict()
        self.cache=dict([(ip,asn) for ip, asn, city, lat, lon in self.getIP2ASN()])
        print '[+] DB: got %d entries in IP2ASN'%(len(self.cache))
        # resolve all new ips to asn
        self.cacheIPstoASN()
        self.commit()
        user2ASN=set()
        print '[+] make user2ASN'
        for u,asn,cc in self.getCountries():
            user2ASN.add((u,asn))
        print '[+] save user2ASN'
        ret=self.addMultipleUser2ASN(user2ASN)
        self.commit()
        print '[+] user2ASN commited new:%d total:%d'%(ret,len(user2ASN))
    
    def distanceRisk(self):
        import geopy
        import geopy.distance
        # get all users        
        for user, in self.session.query(Logins.user).distinct():
            logins = [x for x in self.session.query(Logins,IP2ASN).join(IP2ASN, 
                        Logins.src == IP2ASN.ip).filter(Logins.user == user).\
                        order_by(Logins.ts)]
            if len(logins)<2:
                print '%s skip'%(user)
                continue
            prev_login,prev_ip2asn=logins[0]
            #(prev_ts,prev_user,prev_src,prev_asn,prev_city,\
            # prev_lat,prev_lon) = logins[0]
            #prev_ts = datetime.datetime.strptime(prev_login.ts, "%Y-%m-%d %H:%M:%S.000000")
            prev_pos = geopy.Point(prev_ip2asn.lat, prev_ip2asn.lon)
            totalkm=0
            #for ts,user,src,asn,city,lat,lon in logins[1:]:
            for login,ip2asn in logins[1:]:
                #ts = datetime.datetime.strptime(login.ts,"%Y-%m-%d %H:%M:%S.000000")
                pos = geopy.Point(ip2asn.lat, ip2asn.lon)
                # FIXME: assertions are... not foolproof
                # we should also check that asn.cc == ip2asn.location.cc from geoip
                if ((pos != prev_pos) and
                    (ip2asn.city is not None and prev_ip2asn.city is not None) and
                    (ip2asn.asn != prev_ip2asn.asn)):
                    dist = geopy.distance.distance(prev_pos, pos).km
                    totalkm+=dist
                    duration = (login.ts-prev_login.ts).total_seconds()/3600
                    speed= dist/duration
                    log.debug('%4.2f km/h (%2.2f/%4.2f)'%(speed,dist,(login.ts-prev_login.ts).total_seconds()))
                    if (speed > 300) and (dist > 400): # > 100km/h # FIXME, 400 km for bad geoip
                        print ("A: %s|%4.0f km/h '%s'->'%s'\t(%4.0f km|%2.2f h)"%(
                                user, speed, prev_ip2asn.city, ip2asn.city, dist, duration)).encode('utf-8', 'ignore')
                        print "\ta-",prev_login.ts, prev_ip2asn
                        print "\tb-",login.ts, ip2asn
                # else continue and switch
                prev_pos=pos
                #prev_ts=ts
                prev_login=login
                prev_ip2asn=ip2asn
            print '%s done - %4.0f km'%(user,totalkm)
            

    def stats(self):
        nb_users = self.session.query(Logins.user).distinct().count()
        nb_src = self.session.query(Logins.src).distinct().count()
        nb_asn = self.session.query(ASN.asn).distinct().count()
        print '[+] users: %d'%(nb_users)
        print '[+] src IPS: %d'%(nb_src)
        print '[+] src ASN: %d'%(nb_asn)
        # show distance-based risks
        self.distanceRisk()
        # show countries
        countries=dict()
        users_cc=dict()
        users_asn=dict()
        asn_country_cache=dict([(asn,cc) 
                for asn,prefix,cc in self.getASNCache()])
        try:
            for date,time,user,src,asn,cc in self.getFullLogin():
                if cc not in countries:
                    countries[cc]=0
                if user not in users_asn:
                    users_asn[user]=[]
                    users_cc[user]=[]
                countries[cc]+=1
                users_asn[user].append(asn)
                users_cc[user].append(cc)
        except sqlite3.OperationalError,e:
            import code
            code.interact(local=locals())
        # make stats about rare asn for user X
        from itertools import groupby
        for user, asns in users_asn.items():
            asns.sort()
            freq=[(len(list(group)),asn) for asn, group in groupby(asns)]
            freq.sort()
            if len(freq) == 1: #ignore 
                pass
            else:
                print user,
                for nb,asn in freq:
                    print '(%d,%d,%s)'%(nb,asn,asn_country_cache[asn]),
                print
                

''' Prints number of logins per VPN server.'''
class StatsWorker(DB):
    stats=None
    def cacheStats(self):
        if self.stats is not None:
            return
        stats=dict()
        rows = self.cursor.execute(
                    'SELECT server,count(1) FROM logins GROUP BY server')
        total=0
        for server,cnt in rows:
            total+=cnt
            stats[server]=cnt
        stats["TOTAL"]=total
        self.stats=stats
        
    def __str__(self):
        self.cacheStats()
        retstr=""
        for k,v in self.stats.items():
            if k != "TOTAL":
                retstr+="%s\t%s:\t%d logins\n"%(k,GW[k],v)
                
        retstr+="TOTAL: %d logins"%(self.stats["TOTAL"])
        return retstr

        
def process(afile):
    w = Worker()
    cnt = 0
    logins=[]
    with open(afile, 'rb') as csvfile:
        loginreader = csv.reader(csvfile, delimiter=' ', quotechar='"')
        # ignore header
        loginreader.next()
        #"Number" "Date" "Time" "Interface" "Origin" "Type" "Action" "Service" 
        #"Source Port" "Source" "Destination" "Protocol" "Rule" "Rule Name" 
        #"Current Rule Number" "User" "XlateSrc" "XlateDst" "XlateSPort" 
        #"XlateDPort" "Partner" "Community" "Information" "Source Key ID" 
        #"Destination Key ID" "Encryption Scheme" "Encryption Methods" 
        #"IKE Initiator Cookie" "IKE Responder Cookie" "IKE Phase2 Message ID" 
        #"VPN Peer Gateway" "VPN Feature" "Product"
        #
        #n,d,t,ife,ori,typ,act,serv,srcport,src,dst,prot,r,rn,crn,user,xsrc,xld,
        #xlsp,xldp,p,com,info,srck,destk,enc,encm,ikeinit,ikeresp,ike2,peer,
        #feat,product
        for (id,d,t,ife,ori,typ,act,serv,srcport,src,dst,prot,r,rn,crn,user,
             xsrc,xld,xlsp,xldp,p,com,info,srck,destk,enc,encm,ikeinit,ikeresp,
             ike2,peer,feat,product) in loginreader:
            #print ', '.join([id,d,t,user,src,dst])
            # ID is not unique accross log files
            ## FIXME, we need DATE, TIMESTAMP for d and t.
            # time.strptime(s,"%d%b%Y|%H:%M:%S")
            ts=time.mktime(time.strptime('%s %s'%(d,t),"%d%b%Y %H:%M:%S"))
            w.addLogin(id,d,t,user,src,dst,ts)
            logins.append((id,d,t,user,src,dst,ts))
            cnt+=1
            if (cnt%100)==0:
                w.commit()
                logins=[]
        if (cnt%100):
            w.addMultipleLogin(logins)
        w.commit()
        print 'comsumed %d logins for %s'%(cnt,afile)
    return cnt
        

def main():
    rootparser = argparse.ArgumentParser(description='Read checkpoint PVN logs')
    rootparser.add_argument('--debug', action='store_true', help='Debug mode on.')
    rootparser.add_argument('--dbname', type=str, action='store', 
                            default='alllogins.db', help='Debug mode on.')
    subparsers = rootparser.add_subparsers(help='sub-command help')
    consume_p = subparsers.add_parser('consume', 
        help='Consume log file and inserts in DB.')
    consume_p.set_defaults(func=consume)
    consume_p.add_argument('logfolder', type=str, action='store', default="logs", 
        help='Folder that contains CP VPN log files.')

    resolve_p = subparsers.add_parser('resolve', help='Resolve IP metadata.')
    resolve_p.set_defaults(func=resolve)

    stats_p = subparsers.add_parser('stats', help='Outputs some stats.')
    stats_p.set_defaults(func=stats)

    clean_p = subparsers.add_parser('clean', help='Reset the IP metadata tables.')
    clean_p.set_defaults(func=clean)

    fix_p = subparsers.add_parser('fix', help='Fix some data post resolve.')
    fix_p.set_defaults(func=fix)

    args = rootparser.parse_args()
    
    level=logging.INFO
    if args.debug:
        level=logging.DEBUG
    logging.basicConfig(level=level)
    
    args.func(args)
    

def consume(args):
    from os import listdir
    from os.path import isfile, join
    logfolder=args.logfolder
    files = [ os.path.sep.join([logfolder,f]) for f in listdir(logfolder) if isfile(join(logfolder,f)) ]
    print 'Parsing %d log files'%(len(files))
    #print files
    totalcnt=0
    for f in files:
        totalcnt+=process(f)
    print 'TOTAL: consumed %d logins'%(totalcnt)
    stats = StatsWorker()
    print stats
    
def resolve(args):
    w = AnalysisWorker(args.dbname)
    w.resolve()

def stats(args):
    w = AnalysisWorker(args.dbname)
    w.stats()

def clean(args):
    w = DB(args.dbname)
    w.clean()

def fix(args):
    w = FixWorker(args.dbname)
    #FIXME DEBUG 
    w.fixLoginsTS()
    w.fixIP2ASN()
     


    
if __name__ == "__main__":
    main()
