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

import geopy
import geopy.distance
import pygeoip
import IPy
from cymru.ip2asn.dns import DNSClient as ip2asn

from utils import Memoized

log=logging.getLogger('audit')

DATADB='data/alllogins.db'

GEOIP_CITIES='geoip/berkelydb/hip_ip4_city_lat_lng.db'
GEOIP_COUNTRIES='geoip/berkelydb/hip_ip4_country.db'

MAXMIND_CITIES='geoip/maxmind/GeoLiteCity.dat'
MAXMIND_COUNTRIES='geoip/maxmind/GeoIP.dat'
MAXMIND_ASN='geoip/maxmind/GeoIPASNum.dat'

from conf import GW

import codecs
import locale
sys.stdout = codecs.getwriter(locale.getpreferredencoding())(sys.stdout);

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
        if city is None:
            return None
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
        
    def clean(self):
        if self._conn is not None:
            self._conn.close()
            self._conn=None
        _conn = sqlite3.connect(DATADB)
        for t in ['ip2asn','user2asn']:
            try:
                _conn.cursor().execute('DROP TABLE %s'%(t))
            except sqlite3.OperationalError,e:
                print 'error on drop table',t,e
        _conn.commit()

'''Fix stuff in DB'''
class FixWorker(DB):
    cymru_client = ip2asn()
    geoip = pygeoip.GeoIP(MAXMIND_CITIES, pygeoip.MEMORY_CACHE)
    free_ip2city = bsddb.btopen(GEOIP_CITIES)
    free_allips=[int(x) for x in free_ip2city.keys()]
    free_allips.sort()

    def fix_logins_ts(self):
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
        
    @Memoized
    def get_location(self, ip):
        ''' Uses maxmind DB  to find location '''
        ipObj = IPy.IP(ip)
        if ipObj.iptype() == 'PRIVATE':
            # FIXME use internal knowledge
            return None
        location = self.geoip.record_by_addr(ip)
        if location is None or location['city'] == '': #is None:
            return None
        return location

    @Memoized
    def get_location_harder(self, ip):
        ''' Uses maxmind DB and the free geoip database to find location '''
        ipObj = IPy.IP(ip)
        if ipObj.iptype() == 'PRIVATE':
            return None
        location = self.geoip.record_by_addr(ip)
        if location is None or location['city'] == '': #is None:
            # try free geoip
            res = self.record_by_addr_free_geoip(ip)
            if res is None:
                #print location
                log.info('Unknown IP location : %s - %s'%(ip, location['country_name']))
                return None
            c,lat,lon = res
            location = dict()
            location['city'] = '%s (Approx)'%c
            location['latitude'] = lat
            location['longitude'] = lon
        return location

    def record_by_addr_free_geoip(self, ip):
        ''' Uses the free geoip database to try and find alternate location '''
        #
        asn = self.cymru_client.lookup(ip)
        ipObj = IPy.IP(ip)
        # get all known geoip sorted
        # go through all geoip, to find closest geoip from ipObj
        try:
            ind_geoip=0
            prefix=IPy.IP(asn.prefix)
            try:
                location = self.free_ip2city[str(prefix.int())]
                city,lat,lon = location.split(' ')
                return (city,lat,lon)
            except KeyError,e:
                pass # not so easy
            # find closest head
            while ind_geoip < len(self.free_allips) and (self.free_allips[ind_geoip]<=ipObj.int()):
                ind_geoip+=1
            # ignore IndexError
            prefix_geoip=IPy.IP(self.free_allips[ind_geoip-1])
            if prefix_geoip not in prefix:
                log.debug(' %s cymru_prefix %s !contains geoip %s %s'%
                          (ipObj.ip,prefix,prefix_geoip, IPy.IP(self.free_allips[ind_geoip])))
                
                location = self.free_ip2city[str(prefix_geoip.int())]
                city,lat,lon = location.split(' ')
                return (city,lat,lon)
            # fix the ip2asn entry
        except StopIteration,e:
            pass
        return None

    def fix_IP2ASN_location(self):
        ''' get null-cities IP and fix them'''
        misses=0
        fixes=0
        log.info('[+] fix location - %d NULL cities'%(session.query(IP2ASN)\
                                    .filter(IP2ASN.city == None).count()))
        for ipObj in self.session.query(IP2ASN).filter(IP2ASN.city == None):
            location = self.get_location_harder(ipObj.ip)
            if location is None:
                misses += 1
                continue
            ipObj.city = location['city']
            ipObj.lat = location['latitude']
            ipObj.lon = location['longitude']
            log.debug('FIXED %s'%(ipObj))
            fixes+=1
        self.session.commit()
        log.info('[+] IP2ASN maxmind geoip location FIXED:%d MISSES:%d'%(fixes,misses))

    def check_private_range(self,ip):
        # check for PRIVATe prefix before
        ip_ip = IPy.IP(ip)
        if ip_ip.iptype() == 'PRIVATE':
            bits = ip_ip.strBin()
            for i in xrange(len(bits), 0, -1):
                if bits[:i] in IPy.IPv4ranges:
                    return True
            raise KeyError('%s should be private'%(ip))
        return False

    def resolve_IP_logins_location_asn(self):
        log.info('[+] resolve_IP_logins_location_asn get all logins')
        # all non resolved ip
        ips = [ip for ip, in self.session.query(Logins.src).filter(~Logins.src.in_(\
                self.session.query(IP2ASN.ip).distinct()))\
              .distinct().all() ]
        #
        log.info('[+] resolve_IP_logins_location_asn resolvemany (%d) user src ips'%(len(ips)) )
        # use it
        misses = cnt = 0
        from cymru.ip2asn.whois import WhoisClient as ip2asn_2
        cymru_client = ip2asn_2()
        for ip,asn in zip(ips, cymru_client.lookupmany(ips,qType='IP')):
            if self.check_private_range(ip):
                # FIXME: self.get_location_private
                self.session.add(IP2ASN(ip=ip, asn='0', city='INTERNAL',lat=None,lon=None))
                cnt += 1
                continue
            if asn.asn is None:
                log.warning('Is %s in unassigned IP space ?'%(ip))
                continue
            asn = ASN(asn=asn.asn, prefix=asn.prefix, cc=asn.cc)
            if self.session.query(ASN).filter(ASN.asn == asn.asn and ASN.prefix == asn.prefix).first() is None:
                self.session.add(asn)
                self.session.commit()
            # get the location from the IP prefix
            location = self.get_location(ip)
            if location is None:
                misses += 1
                self.session.add(IP2ASN(ip=ip, asn=asn.asn, city=None, lat=None, lon=None))
            else:
                cnt += 1
                self.session.add(IP2ASN(ip=ip, asn=asn.asn, city=location['city'], 
                                lat=location['latitude'], lon=location['longitude']))
            if ((cnt+misses)%10)==0:
                self.session.commit()
        self.session.commit()
        print '[+] resolve_IP_logins_location_asn end resolved:%d misses:%d'%(cnt, misses)
        return cnt
    
    def resolve(self):
        userdict=dict()
        # resolve all new ips to asn
        self.resolve_IP_logins_location_asn()
    

''' Analysis and controllers'''
class AnalysisWorker(FixWorker):
        
    def distanceRisk(self):
        ''' all location data is IN the database already. '''
        #Logins: id, date, time, user, src, server, ts,
        # get all users        
        for user, in self.session.query(Logins.user).distinct():
            logins_ip2asn = [x for x in self.session.query(Logins,IP2ASN).join(IP2ASN,
                            Logins.src == IP2ASN.ip).filter(Logins.user == user).\
                            order_by(Logins.ts)]                        
            if len(logins_ip2asn) < 2:
                log.debug('skipping %s - not enough logins'%(user))
                continue
            # get first location
            prev_location = IP2ASN()
            try:
                while prev_location.city is None:
                    prev_login, prev_location = logins_ip2asn.pop(0)
            except IndexError,e:
                continue
            prev_pos = geopy.Point(prev_location.lat, prev_location.lon)
            totalkm=0
            print '-'*20,user
            for login, location in logins_ip2asn:
                # get next location
                if location.city is None:
                    continue
                pos = geopy.Point(location.lat, location.lon)
                if (pos != prev_pos):
                    dist = geopy.distance.distance(prev_pos, pos).km
                    totalkm += dist
                    duration = (1+(login.ts-prev_login.ts).total_seconds())/3600
                    speed = dist/duration
                    log.debug('%4.2f km/h (%2.2f/%4.2f)'%(speed,dist,(login.ts-prev_login.ts).total_seconds()))
                    if (speed > 300) and (dist > 400): # > 100km/h # FIXME, 400 km for bad geoip
                        print ("A: %s|%4.0f km/h '%s'->'%s'\t(%4.0f km|%2.2f h)"%(
                                user, speed, prev_location.city, location.city, dist, duration))#.encode('utf-8', 'ignore')
                        print "\ta-",prev_login.ts, prev_location
                        print "\tb-",login.ts, location
                # else continue and switch
                prev_pos=pos
                prev_location=location
                prev_login=login
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
        return
        # show countries
        countries=dict()
        users_cc=dict()
        users_asn=dict()
        #asn_country_cache=dict([(asn,cc) 
        #        for asn,prefix,cc in self.getASNCache()])
        try:
            for date,time,user,src,asn,cc in self.session.query(Logins,IP2ASN)\
                            .join(Logins.src == IP2ASN.ip).filter(Logins.user == user).\
                            order_by(Logins.user,ASN.cc):
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
            ## we need DATE, TIMESTAMP for d and t.
            ts=time.mktime(time.strptime('%s %s'%(d,t),"%d%b%Y %H:%M:%S"))
            w.session.add(Login(id=id,date=d,time=t,user=user,src=src,server=dst,ts=ts))
            cnt+=1
            if (cnt%100)==0:
                w.session.commit()
        w.session.commit()
        print '[+] consumed %d logins for %s'%(cnt,afile)
    return cnt
        

def main():
    rootparser = argparse.ArgumentParser(description='Read checkpoint PVN logs')
    rootparser.add_argument('--debug', action='store_true', help='Debug mode on.')
    rootparser.add_argument('--dbname', type=str, action='store', 
                            default=DATADB, help='Debug mode on.')
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
    w.fix_logins_ts()
    w.fix_IP2ASN_location()
     




    
if __name__ == "__main__":
    main()
