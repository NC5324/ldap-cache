package com.atcx.dev.ldap;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.controls.SimplePagedResultsControl;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFReader;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.ejb.Singleton;
import javax.ejb.Startup;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.BiFunction;
import java.util.logging.Logger;

@Startup
@Singleton
public class LdapServerApp {

    private static final Logger log = Logger.getLogger(LdapServerApp.class.getName());
    private static final String staticQuery1 = "static-ldap-query-1";
    private static final String staticQuery2 = "static-ldap-query-2";
    private static final String staticQuery3 = "static-ldap-query-3";

    private InMemoryDirectoryServer inMemoryDirectoryServer;

    @PostConstruct
    public void startLdapServer() {
        try (LDAPConnection sourceLdapConnection = new LDAPConnection("source-ldap-host", 1389, "source-ldap-bind-dn", "source-ldap-bind-password")) {
            // Start in-memory LDAP server
            log.severe("----- Starting in-memory LDAP server");
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("base-dn1", "base-dn2");
            config.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig(UUID.randomUUID().toString(), 44484));
            config.addAdditionalBindCredentials("target-ldap-bind-dn", "target-ldap-bind-password");
            inMemoryDirectoryServer = new InMemoryDirectoryServer(config);
            inMemoryDirectoryServer.startListening();
            log.severe("----- Started in-memory LDAP server on port 44484");

            // Import schema and org structure from resources folder
            log.severe("----- Importing schema");
            importSchema();
            log.severe("----- Importing org structure");
            importOrgStructure();

            // Search and insert users from source LDAP
            log.severe("----- Searching users for static query 1");
            List<Entry> result1 = searchUsers(sourceLdapConnection, staticQuery1, this::searchUsers);
            log.severe(String.format("Found total users: %s for query %s", result1.size(), staticQuery1));

            log.severe("----- Searching users for static query 2");
            List<Entry> result2 = searchUsers(sourceLdapConnection, staticQuery2, this::searchUsers);
            log.severe(String.format("Found total users: %s for query %s", result2.size(), staticQuery2));

            log.severe("----- Searching users for static query 3");
            List<Entry> result3 = searchUsers(sourceLdapConnection, staticQuery3, this::searchUsers);
            log.severe(String.format("Found total users: %s for query %s", result3.size(), staticQuery3));

            log.severe("----- Importing result set 1");
            insertIntoInMemoryLdap(result1);

            log.severe("----- Importing result set 2");
            insertIntoInMemoryLdap(result2);

            log.severe("----- Importing result set 3");
            insertIntoInMemoryLdap(result3);

            log.severe("---- Ldap in-memory server started & loaded with data!");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void importSchema() throws Exception {
        try (InputStream ldifInputStream = getClass().getClassLoader().getResourceAsStream("schema.ldif")) {
            if (ldifInputStream != null) {
                LDIFReader ldifReader = new LDIFReader(ldifInputStream);
                inMemoryDirectoryServer.applyChangesFromLDIF(ldifReader);
            } else {
                log.severe("LDIF file not found in resources folder.");
            }
        }
    }

    private void importOrgStructure() throws Exception {
        try (InputStream ldifInputStream = getClass().getClassLoader().getResourceAsStream("hierarchy.ldif")) {
            if (ldifInputStream != null) {
                LDIFReader ldifReader = new LDIFReader(ldifInputStream);
                inMemoryDirectoryServer.applyChangesFromLDIF(ldifReader);
            } else {
                log.severe("LDIF file not found in resources folder.");
            }
        }
    }

    private void insertIntoInMemoryLdap(List<Entry> entries) {
        for (Entry entry : entries) {
            try {
                inMemoryDirectoryServer.addEntries(entry);
            } catch (Exception e) {
                log.severe("Error inserting user with cNumber: " + entry.getAttributeValue("uid"));
                e.printStackTrace();
            }
        }
    }

    private List<Entry> searchUsers(LDAPConnection sourceLdapConnection, String query, ThrowingTriFunction<LDAPConnection, ASN1OctetString, String, SearchResult, Exception> searchFunction) throws Exception {
        List<Entry> result = new ArrayList<>();
        SearchResult searchResult = searchFunction.apply(sourceLdapConnection, null, query);
        SimplePagedResultsControl response = SimplePagedResultsControl.get(searchResult);
        do {
            List<Entry> mutableEntries = new ArrayList<>();
            List<SearchResultEntry> searchResultEntries = searchResult.getSearchEntries();
            log.severe("Found users: " + searchResultEntries.size());
            searchResultEntries.forEach(searchResultEntry -> {
                Entry mutableEntry = new Entry(searchResultEntry.getDN(), searchResultEntry.getAttributes());
                mutableEntry.removeAttribute("collectiveLanguage");
                mutableEntries.add(mutableEntry);
            });
            result.addAll(mutableEntries);
            searchResult = searchFunction.apply(sourceLdapConnection, response.getCookie(), query);
            response = SimplePagedResultsControl.get(searchResult);
        } while (response.moreResultsToReturn() && result.size() < 10_000);
        return result;
    }

    private SearchResult searchUsers(LDAPConnection sourceLdapConnection, ASN1OctetString resumeCookie, String query) throws Exception {
        SearchRequest searchRequest = new SearchRequest("", SearchScope.SUB, query);
        searchRequest.setControls(new SimplePagedResultsControl(250, resumeCookie));
        return sourceLdapConnection.search(searchRequest);
    }

    @PreDestroy
    public void stopLdapServer() {
        if (inMemoryDirectoryServer != null) {
            inMemoryDirectoryServer.shutDown(true);
        }
    }
}


