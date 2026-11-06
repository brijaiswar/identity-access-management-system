CREATE TABLE iam_system_lock (
    id INTEGER PRIMARY KEY
);

INSERT INTO iam_system_lock (id) VALUES (1);

INSERT INTO permissions (name, resource, action) VALUES
    ('READ_USER', 'user', 'read'),
    ('WRITE_USER', 'user', 'write'),
    ('DELETE_USER', 'user', 'delete'),
    ('USER_READ_ALL', 'users', 'read'),
    ('USER_CREATE', 'users', 'create'),
    ('USER_UPDATE', 'users', 'update'),
    ('USER_ASSIGN_ROLES', 'users', 'assign_roles'),
    ('ROLE_READ', 'roles', 'read'),
    ('ROLE_MANAGE', 'roles', 'manage');

INSERT INTO roles (name) VALUES ('ADMIN'), ('USER');

INSERT INTO role_permissions (role_id, permission_id)
SELECT roles.id, permissions.id
FROM roles CROSS JOIN permissions
WHERE roles.name = 'ADMIN';

INSERT INTO role_permissions (role_id, permission_id)
SELECT roles.id, permissions.id
FROM roles
JOIN permissions ON permissions.name = 'READ_USER'
WHERE roles.name = 'USER';
