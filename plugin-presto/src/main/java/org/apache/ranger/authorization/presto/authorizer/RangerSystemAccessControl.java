/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.ranger.authorization.presto.authorizer;

import com.facebook.presto.common.CatalogSchemaName;
import com.facebook.presto.spi.CatalogSchemaTableName;
import com.facebook.presto.spi.SchemaTableName;
import com.facebook.presto.spi.security.*;
import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static java.util.Locale.ENGLISH;

public class RangerSystemAccessControl
        implements SystemAccessControl {
    private static Logger LOG = LoggerFactory.getLogger(RangerSystemAccessControl.class);

    final public static String RANGER_CONFIG_KEYTAB = "ranger.keytab";
    final public static String RANGER_CONFIG_PRINCIPAL = "ranger.principal";
    final public static String RANGER_CONFIG_USE_UGI = "ranger.use_ugi";
    final public static String RANGER_CONFIG_HADOOP_CONFIG = "ranger.hadoop_config";
    final public static String RANGER_PRESTO_DEFAULT_HADOOP_CONF = "presto-ranger-site.xml";
    final public static String RANGER_PRESTO_SERVICETYPE = "presto";
    final public static String RANGER_PRESTO_APPID = "presto";

    final private RangerBasePlugin rangerPlugin;

    private boolean useUgi = false;

    public RangerSystemAccessControl(Map<String, String> config) {
        super();

        Configuration hadoopConf = new Configuration();
        if (config.get(RANGER_CONFIG_HADOOP_CONFIG) != null) {
            URL url =  hadoopConf.getResource(config.get(RANGER_CONFIG_HADOOP_CONFIG));
            if (url == null) {
                LOG.warn("Hadoop config " + config.get(RANGER_CONFIG_HADOOP_CONFIG) + " not found");
            } else {
                hadoopConf.addResource(url);
            }
        } else {
            URL url = hadoopConf.getResource(RANGER_PRESTO_DEFAULT_HADOOP_CONF);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Trying to load Hadoop config from " + url + " (can be null)");
            }
            if (url != null) {
                hadoopConf.addResource(url);
            }
        }
        UserGroupInformation.setConfiguration(hadoopConf);

        if (config.get(RANGER_CONFIG_KEYTAB) != null && config.get(RANGER_CONFIG_PRINCIPAL) != null) {
            String keytab = config.get(RANGER_CONFIG_KEYTAB);
            String principal = config.get(RANGER_CONFIG_PRINCIPAL);

            LOG.info("Performing kerberos login with principal " + principal + " and keytab " + keytab);

            try {
                UserGroupInformation.loginUserFromKeytab(principal, keytab);
            } catch (IOException ioe) {
                LOG.error("Kerberos login failed", ioe);
                throw new RuntimeException(ioe);
            }
        }

        if (config.getOrDefault(RANGER_CONFIG_USE_UGI, "false").equalsIgnoreCase("true")) {
            useUgi = true;
        }

        rangerPlugin = new RangerBasePlugin(RANGER_PRESTO_SERVICETYPE, RANGER_PRESTO_APPID);
        rangerPlugin.init();
        rangerPlugin.setResultProcessor(new RangerDefaultAuditHandler());
    }


    /** FILTERING AND DATA MASKING **/

    private RangerAccessResult getDataMaskResult(RangerPrestoAccessRequest request) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("==> getDataMaskResult(request=" + request + ")");
        }

        RangerAccessResult ret = rangerPlugin.evalDataMaskPolicies(request, null);

        if(LOG.isDebugEnabled()) {
            LOG.debug("<== getDataMaskResult(request=" + request + "): ret=" + ret);
        }

        return ret;
    }

    private RangerAccessResult getRowFilterResult(RangerPrestoAccessRequest request) {
        if(LOG.isDebugEnabled()) {
            LOG.debug("==> getRowFilterResult(request=" + request + ")");
        }

        RangerAccessResult ret = rangerPlugin.evalRowFilterPolicies(request, null);

        if(LOG.isDebugEnabled()) {
            LOG.debug("<== getRowFilterResult(request=" + request + "): ret=" + ret);
        }

        return ret;
    }

    private boolean isDataMaskEnabled(RangerAccessResult result) {
        return result != null && result.isMaskEnabled();
    }

    private boolean isRowFilterEnabled(RangerAccessResult result) {
        return result != null && result.isRowFilterEnabled();
    }



    @Override
    public Set<String> filterCatalogs(Identity identity, AccessControlContext context, Set<String> catalogs) {
       /* LOG.debug("==> RangerSystemAccessControl.filterCatalogs("+ catalogs + ")");
        Set<String> filteredCatalogs = new HashSet<>(catalogs.size());
        for (String catalog: catalogs) {
            if (hasPermission(createResource(catalog), identity, context, PrestoAccessType.SELECT)) {
                filteredCatalogs.add(catalog);
            }
        }
        return filteredCatalogs;*/

        return catalogs;
    }

    @Override
    public Set<String> filterSchemas(Identity identity, AccessControlContext context, String catalogName, Set<String> schemaNames) {
       /* LOG.debug("==> RangerSystemAccessControl.filterSchemas(" + catalogName + ")");
        Set<String> filteredSchemaNames = new HashSet<>(schemaNames.size());
        for (String schemaName: schemaNames) {
            if (hasPermission(createResource(catalogName, schemaName), identity, context, PrestoAccessType.SELECT)) {
                filteredSchemaNames.add(schemaName);
            }
        }
        return filteredSchemaNames;*/
        return schemaNames;
    }

    @Override
    public Set<SchemaTableName> filterTables(Identity identity, AccessControlContext context, String catalogName, Set<SchemaTableName> tableNames) {
        LOG.debug("==> RangerSystemAccessControl.filterTables(" + catalogName + ")");
        Set<SchemaTableName> filteredTableNames = new HashSet<>(tableNames.size());
        for (SchemaTableName tableName : tableNames) {
            RangerPrestoResource res = createResource(catalogName, tableName.getSchemaName(), tableName.getTableName());
            if (hasPermission(res, identity, context, PrestoAccessType.SELECT)) {
                filteredTableNames.add(tableName);
            }
        }
        return filteredTableNames;
    }

    /** PERMISSION CHECKS ORDERED BY SYSTEM, CATALOG, SCHEMA, TABLE, VIEW, COLUMN, QUERY, FUNCTIONS, PROCEDURES **/

    /** SYSTEM **/

    @Override
    public void checkCanSetSystemSessionProperty(Identity identity, AccessControlContext context, String propertyName) {
        if (!hasPermission(createSystemPropertyResource(propertyName), identity, context, PrestoAccessType.ALTER)) {
            LOG.debug("RangerSystemAccessControl.checkCanSetSystemSessionProperty denied");
            AccessDeniedException.denySetSystemSessionProperty(propertyName);
        }
    }

    @Override
    public void checkCanSetUser(Identity identity, AccessControlContext context, Optional<Principal> principal, String userName) {
        // pass as it is deprecated
    }

    @Override
    public void checkQueryIntegrity(Identity identity, AccessControlContext context, String query) {

    }

    /** CATALOG **/
    @Override
    public void checkCanSetCatalogSessionProperty(Identity identity, AccessControlContext context, String catalogName, String propertyName) {
        if (!hasPermission(createCatalogSessionResource(catalogName, propertyName),identity, context, PrestoAccessType.ALTER)) {
            LOG.debug("RangerSystemAccessControl.checkCanSetCatalogSessionProperty(" + catalogName + ") denied");
            AccessDeniedException.denySetCatalogSessionProperty(catalogName, propertyName);
        }
    }

    @Override
    public void checkCanAccessCatalog(Identity identity, AccessControlContext context, String catalogName) {
        createResource(catalogName);
        /*if (!hasPermission(createResource(catalogName), identity, context, PrestoAccessType.USE)) {
            LOG.debug("RangerSystemAccessControl.checkCanAccessCatalog(" + catalogName + ") denied");
            AccessDeniedException.denyCatalogAccess(catalogName);
        }*/
    }

    @Override
    public void checkCanShowSchemas(Identity identity, AccessControlContext context, String catalogName) {
        createResource(catalogName);
       /* if (!hasPermission(createResource(catalogName), identity, context, PrestoAccessType.SHOW)) {
            LOG.debug("RangerSystemAccessControl.checkCanShowSchemas(" + catalogName + ") denied");
            AccessDeniedException.denyShowSchemas(catalogName);
        }*/
    }

    /**
     * Create schema is evaluated on the level of the Catalog. This means that it is assumed you have permission
     * to create a schema when you have create rights on the catalog level
     */
    @Override
    public void checkCanCreateSchema(Identity identity, AccessControlContext context, CatalogSchemaName schema) {
        if (!hasPermission(createResource(schema.getCatalogName()), identity, context, PrestoAccessType.CREATE)) {
            LOG.debug("RangerSystemAccessControl.checkCanCreateSchema(" + schema.getSchemaName() + ") denied");
            AccessDeniedException.denyCreateSchema(schema.getSchemaName());
        }
    }

    /**
     * This is evaluated against the schema name as ownership information is not available
     */
    @Override
    public void checkCanDropSchema(Identity identity, AccessControlContext context, CatalogSchemaName schema) {
        if (!hasPermission(createResource(schema.getCatalogName(), schema.getSchemaName()), identity, context, PrestoAccessType.DROP)) {
            LOG.debug("RangerSystemAccessControl.checkCanDropSchema(" + schema.getSchemaName() + ") denied");
            AccessDeniedException.denyDropSchema(schema.getSchemaName());
        }
    }

    /**
     * This is evaluated against the schema name as ownership information is not available
     */
    @Override
    public void checkCanRenameSchema(Identity identity, AccessControlContext context, CatalogSchemaName schema, String newSchemaName) {
        RangerPrestoResource res = createResource(schema.getCatalogName(), schema.getSchemaName());
        if (!hasPermission(res, identity, context, PrestoAccessType.ALTER)) {
            LOG.debug("RangerSystemAccessControl.checkCanRenameSchema(" + schema.getSchemaName() + ") denied");
            AccessDeniedException.denyRenameSchema(schema.getSchemaName(), newSchemaName);
        }
    }

    /**
     * Create table is verified on schema level
     */
    @Override
    public void checkCanCreateTable(Identity identity, AccessControlContext context, CatalogSchemaTableName table) {
        if (!hasPermission(createResource(table.getCatalogName(), table.getSchemaTableName().getSchemaName()),identity, context, PrestoAccessType.CREATE)) {
            LOG.debug("RangerSystemAccessControl.checkCanCreateTable(" + table.getSchemaTableName().getTableName() + ") denied");
            AccessDeniedException.denyCreateTable(table.getSchemaTableName().getTableName());
        }
    }

    /**
     * This is evaluated against the table name as ownership information is not available
     */
    @Override
    public void checkCanDropTable(Identity identity, AccessControlContext context, CatalogSchemaTableName table) {
        if (!hasPermission(createResource(table), identity, context, PrestoAccessType.DROP)) {
            LOG.debug("RangerSystemAccessControl.checkCanDropTable(" + table.getSchemaTableName().getTableName() + ") denied");
            AccessDeniedException.denyDropTable(table.getSchemaTableName().getTableName());
        }
    }

    /**
     * This is evaluated against the table name as ownership information is not available
     */
    @Override
    public void checkCanRenameTable(Identity identity, AccessControlContext context, CatalogSchemaTableName table, CatalogSchemaTableName newTable) {
        RangerPrestoResource res = createResource(table);
        if (!hasPermission(res, identity, context, PrestoAccessType.ALTER)) {
            LOG.debug("RangerSystemAccessControl.checkCanRenameTable(" + table.getSchemaTableName().getTableName() + ") denied");
            AccessDeniedException.denyRenameTable(table.getSchemaTableName().getTableName(), newTable.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanShowTablesMetadata(Identity identity, AccessControlContext context, CatalogSchemaName schema) {
        // SystemAccessControl.super.checkCanShowTablesMetadata(identity, context, schema);
    }

    @Override
    public void checkCanInsertIntoTable(Identity identity, AccessControlContext context, CatalogSchemaTableName table) {
        RangerPrestoResource res = createResource(table);
        if (!hasPermission(res, identity, context, PrestoAccessType.INSERT)) {
            LOG.debug("RangerSystemAccessControl.checkCanInsertIntoTable(" + table.getSchemaTableName().getTableName() + ") denied");
            AccessDeniedException.denyInsertTable(table.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanDeleteFromTable(Identity identity, AccessControlContext context, CatalogSchemaTableName table) {
        if (!hasPermission(createResource(table), identity, context, PrestoAccessType.DELETE)) {
            LOG.debug("RangerSystemAccessControl.checkCanDeleteFromTable(" + table.getSchemaTableName().getTableName() + ") denied");
            AccessDeniedException.denyDeleteTable(table.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanGrantTablePrivilege(Identity identity, AccessControlContext context, Privilege privilege, CatalogSchemaTableName table, PrestoPrincipal grantee, boolean withGrantOption) {
        if (!hasPermission(createResource(table), identity, context, PrestoAccessType.GRANT)) {
            LOG.debug("RangerSystemAccessControl.checkCanGrantTablePrivilege(" + table + ") denied");
            AccessDeniedException.denyGrantTablePrivilege(privilege.toString(), table.toString());
        }
    }

    @Override
    public void checkCanRevokeTablePrivilege(Identity identity, AccessControlContext context, Privilege privilege, CatalogSchemaTableName table, PrestoPrincipal revokee, boolean grantOptionFor) {
        if (!hasPermission(createResource(table), identity, context, PrestoAccessType.REVOKE)) {
            LOG.debug("RangerSystemAccessControl.checkCanRevokeTablePrivilege(" + table + ") denied");
            AccessDeniedException.denyRevokeTablePrivilege(privilege.toString(), table.toString());
        }
    }

    /**
     * Create view is verified on schema level
     */
    @Override
    public void checkCanCreateView(Identity identity, AccessControlContext context, CatalogSchemaTableName view) {
        if (!hasPermission(createResource(view.getCatalogName(), view.getSchemaTableName().getSchemaName()), identity, context, PrestoAccessType.CREATE)) {
            LOG.debug("RangerSystemAccessControl.checkCanCreateView(" + view.getSchemaTableName().getTableName() + ") denied");
            AccessDeniedException.denyCreateView(view.getSchemaTableName().getTableName());
        }
    }

    /**
     * This is evaluated against the table name as ownership information is not available
     */
    @Override
    public void checkCanDropView(Identity identity, AccessControlContext context, CatalogSchemaTableName view) {
        if (!hasPermission(createResource(view), identity, context, PrestoAccessType.DROP)) {
            LOG.debug("RangerSystemAccessControl.checkCanDropView(" + view.getSchemaTableName().getTableName() + ") denied");
            AccessDeniedException.denyDropView(view.getSchemaTableName().getTableName());
        }
    }

    /**
     * This check equals the check for checkCanCreateView
     */
    @Override
    public void checkCanCreateViewWithSelectFromColumns(Identity identity, AccessControlContext context, CatalogSchemaTableName table, Set<String> columns) {
        try {
            checkCanCreateView(identity, context, table);
        } catch (AccessDeniedException ade) {
            LOG.debug("RangerSystemAccessControl.checkCanCreateViewWithSelectFromColumns(" + table.getSchemaTableName().getTableName() + ") denied");
            AccessDeniedException.denyCreateViewWithSelect(table.getSchemaTableName().getTableName(), identity);
        }
    }

    /** COLUMN **/

    /**
     * This is evaluated on table level
     */
    @Override
    public void checkCanAddColumn(Identity identity, AccessControlContext context, CatalogSchemaTableName table) {
        RangerPrestoResource res = createResource(table);
        if (!hasPermission(res, identity, context, PrestoAccessType.ALTER)) {
            AccessDeniedException.denyAddColumn(table.getSchemaTableName().getTableName());
        }
    }

    /**
     * This is evaluated on table level
     */
    @Override
    public void checkCanDropColumn(Identity identity, AccessControlContext context, CatalogSchemaTableName table) {
        RangerPrestoResource res = createResource(table);
        if (!hasPermission(res, identity, context, PrestoAccessType.DROP)) {
            LOG.debug("RangerSystemAccessControl.checkCanDropColumn(" + table.getSchemaTableName().getTableName() + ") denied");
            AccessDeniedException.denyDropColumn(table.getSchemaTableName().getTableName());
        }
    }

    /**
     * This is evaluated on table level
     */
    @Override
    public void checkCanRenameColumn(Identity identity, AccessControlContext context, CatalogSchemaTableName table) {
        RangerPrestoResource res = createResource(table);
        if (!hasPermission(res, identity, context, PrestoAccessType.ALTER)) {
            LOG.debug("RangerSystemAccessControl.checkCanRenameColumn(" + table.getSchemaTableName().getTableName() + ") denied");
            AccessDeniedException.denyRenameColumn(table.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanSelectFromColumns(Identity identity, AccessControlContext context, CatalogSchemaTableName table, Set<String> columns) {
        for (RangerPrestoResource res : createResource(table, columns)) {
            if (!hasPermission(res, identity, context, PrestoAccessType.SELECT)) {
                LOG.debug("RangerSystemAccessControl.checkCanSelectFromColumns(" + table.getSchemaTableName().getTableName() + ") denied");
                AccessDeniedException.denySelectColumns(table.getSchemaTableName().getTableName(), columns);
            }
        }
    }

    /** HELPER FUNCTIONS **/

    private RangerPrestoAccessRequest createAccessRequest(RangerPrestoResource resource, Identity identity, AccessControlContext context, PrestoAccessType accessType) {
        String userName = null;
        Set<String> userGroups = null;

        if (useUgi) {
            UserGroupInformation ugi = UserGroupInformation.createRemoteUser(identity.getUser());

            userName = ugi.getShortUserName();
            String[] groups = ugi != null ? ugi.getGroupNames() : null;

            if (groups != null && groups.length > 0) {
                userGroups = new HashSet<>(Arrays.asList(groups));
            }
        } else {
            userName = identity.getUser();
         //   userGroups = identity.getGroups();    // 该版本不支持  zfq
        }

        RangerPrestoAccessRequest request = new RangerPrestoAccessRequest(
                resource,
                userName,
                userGroups,
                accessType
        );

        return request;
    }

    private boolean hasPermission(RangerPrestoResource resource, Identity identity, AccessControlContext context, PrestoAccessType accessType) {
        boolean ret = false;

        RangerPrestoAccessRequest request = createAccessRequest(resource, identity, context, accessType);

        RangerAccessResult result = rangerPlugin.isAccessAllowed(request);
        if (result != null && result.getIsAllowed()) {
            ret = true;
        }

        return ret;
    }

    private static RangerPrestoResource createUserResource(String userName) {
        RangerPrestoResource res = new RangerPrestoResource();
        res.setValue(RangerPrestoResource.KEY_USER, userName);

        return res;
    }

    private static RangerPrestoResource createFunctionResource(String function) {
        RangerPrestoResource res = new RangerPrestoResource();
        res.setValue(RangerPrestoResource.KEY_FUNCTION, function);

        return res;
    }

    private static RangerPrestoResource createCatalogSessionResource(String catalogName, String propertyName) {
        RangerPrestoResource res = new RangerPrestoResource();
        res.setValue(RangerPrestoResource.KEY_CATALOG, catalogName);
        res.setValue(RangerPrestoResource.KEY_SESSION_PROPERTY, propertyName);

        return res;
    }

    private static RangerPrestoResource createSystemPropertyResource(String property) {
        RangerPrestoResource res = new RangerPrestoResource();
        res.setValue(RangerPrestoResource.KEY_SYSTEM_PROPERTY, property);

        return res;
    }

    private static RangerPrestoResource createResource(CatalogSchemaName catalogSchemaName) {
        return createResource(catalogSchemaName.getCatalogName(), catalogSchemaName.getSchemaName());
    }

    private static RangerPrestoResource createResource(CatalogSchemaTableName catalogSchemaTableName) {
        return createResource(catalogSchemaTableName.getCatalogName(),
                catalogSchemaTableName.getSchemaTableName().getSchemaName(),
                catalogSchemaTableName.getSchemaTableName().getTableName());
    }

    private static RangerPrestoResource createResource(String catalogName) {
        return new RangerPrestoResource(catalogName, Optional.empty(), Optional.empty());
    }

    private static RangerPrestoResource createResource(String catalogName, String schemaName) {
        return new RangerPrestoResource(catalogName, Optional.of(schemaName), Optional.empty());
    }

    private static RangerPrestoResource createResource(String catalogName, String schemaName, final String tableName) {
        return new RangerPrestoResource(catalogName, Optional.of(schemaName), Optional.of(tableName));
    }

    private static RangerPrestoResource createResource(String catalogName, String schemaName, final String tableName, final Optional<String> column) {
        return new RangerPrestoResource(catalogName, Optional.of(schemaName), Optional.of(tableName), column);
    }

    private static List<RangerPrestoResource> createResource(CatalogSchemaTableName table, Set<String> columns) {
        List<RangerPrestoResource> colRequests = new ArrayList<>();

        if (columns.size() > 0) {
            for (String column : columns) {
                RangerPrestoResource rangerPrestoResource = createResource(table.getCatalogName(),
                        table.getSchemaTableName().getSchemaName(),
                        table.getSchemaTableName().getTableName(), Optional.of(column));
                colRequests.add(rangerPrestoResource);
            }
        } else {
            colRequests.add(createResource(table.getCatalogName(),
                    table.getSchemaTableName().getSchemaName(),
                    table.getSchemaTableName().getTableName(), Optional.empty()));
        }
        return colRequests;
    }
}

class RangerPrestoResource
        extends RangerAccessResourceImpl {


    public static final String KEY_CATALOG = "catalog";
    public static final String KEY_SCHEMA = "schema";
    public static final String KEY_TABLE = "table";
    public static final String KEY_COLUMN = "column";
    public static final String KEY_USER = "prestouser";
    public static final String KEY_FUNCTION = "function";
    public static final String KEY_PROCEDURE = "procedure";
    public static final String KEY_SYSTEM_PROPERTY = "systemproperty";
    public static final String KEY_SESSION_PROPERTY = "sessionproperty";

    public RangerPrestoResource() {
    }

    public RangerPrestoResource(String catalogName, Optional<String> schema, Optional<String> table) {
        setValue(KEY_CATALOG, catalogName);
        if (schema.isPresent()) {
            setValue(KEY_SCHEMA, schema.get());
        }
        if (table.isPresent()) {
            setValue(KEY_TABLE, table.get());
        }
    }

    public RangerPrestoResource(String catalogName, Optional<String> schema, Optional<String> table, Optional<String> column) {
        setValue(KEY_CATALOG, catalogName);
        if (schema.isPresent()) {
            setValue(KEY_SCHEMA, schema.get());
        }
        if (table.isPresent()) {
            setValue(KEY_TABLE, table.get());
        }
        if (column.isPresent()) {
            setValue(KEY_COLUMN, column.get());
        }
    }

    public String getCatalogName() {
        return (String) getValue(KEY_CATALOG);
    }

    public String getTable() {
        return (String) getValue(KEY_TABLE);
    }

    public String getCatalog() {
        return (String) getValue(KEY_CATALOG);
    }

    public String getSchema() {
        return (String) getValue(KEY_SCHEMA);
    }

    public Optional<SchemaTableName> getSchemaTable() {
        final String schema = getSchema();
        if (StringUtils.isNotEmpty(schema)) {
            return Optional.of(new SchemaTableName(schema, Optional.ofNullable(getTable()).orElse("*")));
        }
        return Optional.empty();
    }
}

class RangerPrestoAccessRequest
        extends RangerAccessRequestImpl {
    public RangerPrestoAccessRequest(RangerPrestoResource resource,
                                     String user,
                                     Set<String> userGroups,
                                     PrestoAccessType prestoAccessType) {
        super(resource, prestoAccessType.name().toLowerCase(ENGLISH), user, userGroups, null);
        setAccessTime(new Date());
    }
}

enum PrestoAccessType {
    CREATE, DROP, SELECT, INSERT, DELETE, USE, ALTER, ALL, GRANT, REVOKE, SHOW, IMPERSONATE, EXECUTE;
}