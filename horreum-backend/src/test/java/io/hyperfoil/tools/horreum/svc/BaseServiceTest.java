package io.hyperfoil.tools.horreum.svc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.transaction.TransactionManager;
import javax.ws.rs.core.HttpHeaders;

import org.jboss.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInfo;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.hyperfoil.tools.horreum.entity.alerting.Change;
import io.hyperfoil.tools.horreum.entity.alerting.ChangeDetection;
import io.hyperfoil.tools.horreum.entity.alerting.DataPoint;
import io.hyperfoil.tools.horreum.entity.json.Access;
import io.hyperfoil.tools.horreum.entity.json.DataSet;
import io.hyperfoil.tools.horreum.entity.json.Label;
import io.hyperfoil.tools.horreum.entity.json.NamedJsonPath;
import io.hyperfoil.tools.horreum.entity.json.Run;
import io.hyperfoil.tools.horreum.entity.json.Schema;
import io.hyperfoil.tools.horreum.entity.json.Test;
import io.hyperfoil.tools.horreum.entity.json.View;
import io.hyperfoil.tools.horreum.entity.json.ViewComponent;
import io.hyperfoil.tools.horreum.server.CloseMe;
import io.hyperfoil.tools.horreum.server.RoleManager;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import io.smallrye.jwt.build.Jwt;
import io.vertx.core.eventbus.EventBus;

public class BaseServiceTest {
   static final String[] TESTER_ROLES = { "foo-team", "foo-tester", "tester", "viewer" };
   static final String[] UPLOADER_ROLES = { "foo-team", "foo-uploader", "uploader" };
   static final String TESTER_TOKEN = BaseServiceTest.getAccessToken("alice", TESTER_ROLES);
   static final String UPLOADER_TOKEN = BaseServiceTest.getAccessToken("alice", UPLOADER_ROLES);

   protected final Logger log = Logger.getLogger(getClass());

   @Inject
   EntityManager em;
   @Inject
   TransactionManager tm;
   @Inject
   RoleManager roleManager;
   @Inject
   EventBus eventBus;

   @BeforeEach
   public void beforeMethod(TestInfo info) {
      log.infof("Starting test %s.%s", info.getTestClass().map(Class::getSimpleName).orElse("<unknown>"), info.getDisplayName());
   }

   @AfterEach
   public void afterMethod(TestInfo info) {
      log.infof("Completed test %s.%s", info.getTestClass().map(Class::getName).orElse("<unknown>"), info.getDisplayName());
      dropAllViewsAndTests();
      log.infof("Finished cleanup of test %s.%s", info.getTestClass().map(Class::getSimpleName).orElse("<unknown>"), info.getDisplayName());
   }

   protected void dropAllViewsAndTests() {
      Util.withTx(tm, () -> {
         try (CloseMe ignored = roleManager.withRoles(em, Stream.concat(Stream.of(TESTER_ROLES), Stream.of(Roles.HORREUM_SYSTEM)).collect(Collectors.toList()))) {
            em.createNativeQuery("UPDATE test SET defaultview_id = NULL").executeUpdate();
            ViewComponent.deleteAll();
            View.deleteAll();
            em.flush();
            Test.deleteAll();
            Change.deleteAll();
            DataPoint.deleteAll();

            DataSet.deleteAll();
            Run.deleteAll();

            em.createNativeQuery("DELETE FROM label_extractors").executeUpdate();
            Label.deleteAll();
            Schema.deleteAll();
         }
         return null;
      });
   }

   public static Test createExampleTest(String testName) {
      Test test = new Test();
      test.name = testName;
      test.description = "Bar";
      test.owner = TESTER_ROLES[0];
      View defaultView = new View();
      defaultView.name = "Default";
      defaultView.components = new ArrayList<>();
      defaultView.components.add(new ViewComponent("Some column", null, "foo"));
      test.defaultView = defaultView;
      return test;
   }

   public static String getAccessToken(String userName, String... groups) {
      return Jwt.preferredUserName(userName)
            .groups(new HashSet<>(Arrays.asList(groups)))
            .issuer("https://server.example.com")
            .audience("https://service.example.com")
            .jws()
            .keyId("1")
            .sign();
   }

   protected int uploadRun(Object runJson, String test) {
      long timestamp = System.currentTimeMillis();
      return uploadRun(timestamp, timestamp, runJson, test);
   }

   protected int uploadRun(long timestamp, Object runJson, String test) {
      return uploadRun(timestamp, timestamp, runJson, test);
   }

   protected int uploadRun(long start, long stop, Object runJson, String test) {
      String runIdString = RestAssured.given().auth().oauth2(UPLOADER_TOKEN)
            .header(HttpHeaders.CONTENT_TYPE, "application/json")
            .body(runJson)
            .post("/api/run/data?start=" + start + "&stop=" + stop + "&test=" + test + "&owner=foo-team&access=PUBLIC")
            .then()
            .statusCode(200)
            .extract().asString();
      return Integer.parseInt(runIdString);
   }

   protected Test createTest(Test test) {
      return jsonRequest()
            .body(test)
            .post("/api/test")
            .then()
            .statusCode(200)
            .extract().body().as(Test.class);
   }

   protected void deleteTest(Test test) {
      RestAssured.given().auth().oauth2(TESTER_TOKEN)
            .delete("/api/test/" + test.id)
            .then()
            .statusCode(204);
   }

   protected RequestSpecification jsonRequest() {
      return RestAssured.given().auth().oauth2(TESTER_TOKEN)
            .header(HttpHeaders.CONTENT_TYPE, "application/json");
   }

   protected RequestSpecification jsonUploaderRequest() {
      return RestAssured.given().auth().oauth2(UPLOADER_TOKEN)
            .header(HttpHeaders.CONTENT_TYPE, "application/json");
   }

   protected String getTestName(TestInfo info) {
      return info.getTestClass().map(Class::getName).orElse("<unknown>") + "." + info.getDisplayName();
   }

   protected Schema createExampleSchema(TestInfo info) {
      String name = info.getTestClass().map(Class::getName).orElse("<unknown>") + "." + info.getDisplayName();
      Schema schema = createSchema(name, uriForTest(info, "1.0"));
      addLabel(schema, "value", null, new NamedJsonPath("value", "$.value", false));
      return schema;
   }

   protected Schema createSchema(String name, String uri) {
      Schema schema = new Schema();
      schema.owner = TESTER_ROLES[0];
      schema.name = name;
      schema.uri = uri;
      Response response = jsonRequest().body(schema).post("/api/schema");
      response.then().statusCode(200);
      schema.id = Integer.parseInt(response.body().asString());
      return schema;
   }

   protected void deleteSchema(Schema schema) {
      jsonRequest().delete("/api/schema/" + schema.id).then().statusCode(204);
   }

   protected String uriForTest(TestInfo info, String suffix) {
      return "urn:" + info.getTestClass().map(Class::getName).orElse("<unknown>") + ":" + info.getDisplayName() + ":" + suffix;
   }

   protected int addLabel(Schema schema, String name, String function, NamedJsonPath... extractors) {
      return postLabel(schema, name, function, new Label(), extractors);
   }

   protected int updateLabel(Schema schema, int labelId, String name, String function, NamedJsonPath... extractors) {
      Label l = new Label();
      l.id = labelId;
      return postLabel(schema, name, function, l, extractors);
   }

   private int postLabel(Schema schema, String name, String function, Label l, NamedJsonPath[] extractors) {
      l.name = name;
      l.function = function;
      l.schema = schema;
      l.owner = TESTER_ROLES[0];
      l.access = Access.PUBLIC;
      l.extractors = Arrays.asList(extractors);
      Response response = jsonRequest().body(l).post("/api/schema/" + schema.id + "/labels");
      response.then().statusCode(200);
      return Integer.parseInt(response.body().asString());
   }

   protected void deleteLabel(Schema schema, int labelId) {
      jsonRequest().delete("/api/schema/" + schema.id + "/labels/" + labelId).then().statusCode(204);
   }

   protected void setTestVariables(Test test, String name, String label, ChangeDetection... rds) {
      setTestVariables(test, name, Collections.singletonList(label), rds);
   }

   protected void setTestVariables(Test test, String name, List<String> labels, ChangeDetection... rds) {
      ArrayNode variables = JsonNodeFactory.instance.arrayNode();
      ObjectNode variable = JsonNodeFactory.instance.objectNode();
      variable.put("testid", test.id);
      variable.put("name", name);
      variable.set("labels", labels.stream().reduce(JsonNodeFactory.instance.arrayNode(), ArrayNode::add, ArrayNode::addAll));
      if (rds.length > 0) {
         ArrayNode rdsArray = JsonNodeFactory.instance.arrayNode();
         for (ChangeDetection rd : rds) {
            rdsArray.add(JsonNodeFactory.instance.objectNode().put("model", rd.model).set("config", rd.config));
         }
         variable.set("changeDetection", rdsArray);
      }
      variables.add(variable);
      jsonRequest().body(variables.toString()).post("/api/alerting/variables?test=" + test.id).then().statusCode(204);
   }

   protected <E> BlockingQueue<E> eventConsumerQueue(Class<? extends E> eventClass, String eventType) {
      BlockingQueue<E> queue = new LinkedBlockingDeque<>();
      eventBus.consumer(eventType, msg -> {
         if (eventClass.isInstance(msg.body())) {
            queue.add(eventClass.cast(msg.body()));
         }
      });
      return queue;
   }

   protected ArrayNode jsonArray(String... items) {
      ArrayNode array = JsonNodeFactory.instance.arrayNode(items.length);
      for (String item : items) {
         array.add(item);
      }
      return array;
   }

   protected BlockingQueue<Integer> trashRun(int runId) throws InterruptedException {
      BlockingQueue<Integer> trashedQueue = eventConsumerQueue(Integer.class, Run.EVENT_TRASHED);
      jsonRequest().post("/api/run/" + runId + "/trash").then().statusCode(204);
      assertEquals(runId, trashedQueue.poll(10, TimeUnit.SECONDS));
      return trashedQueue;
   }
}
