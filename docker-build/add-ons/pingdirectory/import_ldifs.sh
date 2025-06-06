#!/bin/bash

/opt/pingdirectory/bin/ldapmodify --defaultAdd -h localhost -p 389 -D "cn=administrator" -w Password1 -f /opt/tmp/group.ldif
/opt/pingdirectory/bin/ldapmodify -h localhost -p 389 -D "cn=administrator" -w Password1 \
  -f /opt/tmp/pingamldifs/opendj_user_schema.ldif \
  -f /opt/tmp/pingamldifs/opendj_deviceprint.ldif \
  -f /opt/tmp/pingamldifs/opendj_dashboard.ldif \
  -f /opt/tmp/pingamldifs/opendj_pushdevices.ldif \
  -f /opt/tmp/pingamldifs/opendj_oathdevices.ldif \
  -f /opt/tmp/pingamldifs/opendj_deviceprofiles.ldif \
  -f /opt/tmp/pingamldifs/opendj_webauthndevices.ldif \
  -f /opt/tmp/pingamldifs/opendj_kba.ldif
