package org.zzq.mapper;

import org.apache.ibatis.annotations.*;
import org.zzq.entities.SysUser;

import java.util.List;

@Mapper
public interface UserMapper {
    @Select("select * from sys_user where username = #{username}")
    @Results({
            @Result(id = true, property = "id", column = "id"),
            @Result(property = "roles", column = "id", javaType = List.class,
                    many = @Many(select = "com.itheima.mapper.RoleMapper.findByUid"))
    })
    public SysUser findByName(String username);
}
