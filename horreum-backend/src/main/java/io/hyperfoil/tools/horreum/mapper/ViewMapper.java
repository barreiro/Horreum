package io.hyperfoil.tools.horreum.mapper;

import java.util.Collections;
import java.util.stream.Collectors;

import io.hyperfoil.tools.horreum.api.data.View;
import io.hyperfoil.tools.horreum.entity.data.*;

public class ViewMapper {
    public static View from(ViewDAO v) {
        View dto = new View();
        dto.id = v.id;
        dto.name = v.name;
        dto.testId = v.test.id;
        if (v.components != null)
            dto.components = v.components.stream().map(ViewMapper::fromViewComponent).collect(Collectors.toList());

        return dto;
    }

    public static io.hyperfoil.tools.horreum.api.data.ViewComponent fromViewComponent(ViewComponentDAO vc) {
        io.hyperfoil.tools.horreum.api.data.ViewComponent dto = new io.hyperfoil.tools.horreum.api.data.ViewComponent();
        dto.id = vc.id;
        dto.headerName = vc.headerName;
        dto.headerOrder = vc.headerOrder;
        dto.labels = vc.labels;
        dto.render = vc.render;

        return dto;
    }

    public static ViewDAO to(View dto) {
        ViewDAO v = new ViewDAO();
        v.id = dto.id;
        v.name = dto.name;
        if (dto.testId != null && dto.testId > 0)
            v.test = ViewDAO.getEntityManager().getReference(TestDAO.class, dto.testId);
        if (dto.components != null)
            v.components = dto.components.stream().map(c -> ViewMapper.toViewComponent(c, v)).collect(Collectors.toList());
        else
            v.components = Collections.emptyList();

        return v;
    }

    private static ViewComponentDAO toViewComponent(io.hyperfoil.tools.horreum.api.data.ViewComponent dto, ViewDAO view) {
        ViewComponentDAO vc = new ViewComponentDAO();
        vc.id = dto.id;
        vc.headerName = dto.headerName;
        vc.headerOrder = dto.headerOrder;
        vc.labels = dto.labels;
        vc.render = dto.render;
        vc.view = view;

        return vc;
    }
}
