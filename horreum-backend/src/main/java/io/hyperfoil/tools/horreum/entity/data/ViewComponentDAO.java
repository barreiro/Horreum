package io.hyperfoil.tools.horreum.entity.data;

import java.util.Objects;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.validation.constraints.NotNull;

import org.hibernate.annotations.Type;

import com.fasterxml.jackson.annotation.JsonIgnoreType;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;

import io.hyperfoil.tools.horreum.entity.CustomSequenceGenerator;
import io.hyperfoil.tools.horreum.hibernate.JsonBinaryType;
import io.quarkus.hibernate.orm.panache.PanacheEntityBase;

/**
 * Security model: view components are owned by {@link ViewDAO} and this is owned by {@link TestDAO}, therefore
 * we don't have to retain ownership info.
 */
@Entity(name = "viewcomponent")
@Table(uniqueConstraints = @UniqueConstraint(columnNames = { "view_id", "headerName" }))
@JsonIgnoreType
public class ViewComponentDAO extends PanacheEntityBase {
    @Id
    @CustomSequenceGenerator(name = "viewcomponentidgenerator", allocationSize = 1)
    public Integer id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "view_id")
    public ViewDAO view;

    /**
     * In UI, headers are displayed based on {@link #headerOrder} and then {@link #headerName}.
     */
    @NotNull
    public int headerOrder;

    @NotNull
    public String headerName;

    @NotNull
    @Type(JsonBinaryType.class)
    @Column(columnDefinition = "jsonb")
    public JsonNode labels;

    /**
     * When this is <code>null</code> defaults to rendering as plain text.
     */
    public String render;

    public ViewComponentDAO() {
    }

    public ViewComponentDAO(String headerName, String render, String... labels) {
        this.headerName = headerName;
        ArrayNode labelsNode = JsonNodeFactory.instance.arrayNode();
        for (String l : labels) {
            labelsNode.add(l);
        }
        this.labels = labelsNode;
        this.render = render;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        ViewComponentDAO that = (ViewComponentDAO) o;
        return headerOrder == that.headerOrder &&
                Objects.equals(id, that.id) &&
                Objects.equals(headerName, that.headerName) &&
                Objects.equals(labels, that.labels) &&
                Objects.equals(render, that.render);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, headerOrder, headerName, labels, render);
    }
}
