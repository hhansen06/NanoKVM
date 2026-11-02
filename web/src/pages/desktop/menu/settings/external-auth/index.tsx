import { useEffect, useState } from 'react';
import {
  Alert,
  Button,
  Divider,
  Form,
  Input,
  InputNumber,
  message,
  Select,
  Switch,
  Tabs,
  Tag
} from 'antd';
import type { FormInstance } from 'antd';
import { PlusIcon, Trash2Icon } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import * as api from '@/api/auth.ts';
import type {
  AccountSource,
  ExternalAuthConfig,
  ExternalAuthTestResult,
  ExternalMapping,
  Permission,
  PermissionDescriptor,
  UserRole
} from '@/api/auth.ts';
import { encrypt } from '@/lib/encrypt.ts';
import { permissionLabelKey } from '@/lib/permissions.ts';

// The form keeps the optional default mapping as a switch plus fields, and the
// session lifetime in hours; toConfig turns it back into what the server stores.
type FormMapping = { enabled: boolean; role: UserRole; permissions: Permission[] };

type FormValues = Omit<ExternalAuthConfig, 'sessionDuration' | 'ldap' | 'tacacs'> & {
  sessionHours: number;
  ldap: Omit<ExternalAuthConfig['ldap'], 'defaultMapping'> & { defaultMapping: FormMapping };
  tacacs: Omit<ExternalAuthConfig['tacacs'], 'defaultMapping'> & { defaultMapping: FormMapping };
};

type TestValues = { source: AccountSource; username: string; password: string };

const ORDER_OPTIONS = [
  { value: 'tacacs,ldap', label: 'TACACS+ → LDAP' },
  { value: 'ldap,tacacs', label: 'LDAP → TACACS+' }
];

function toFormMapping(mapping: ExternalMapping | null): FormMapping {
  return mapping
    ? { enabled: true, role: mapping.role, permissions: mapping.permissions ?? [] }
    : { enabled: false, role: 'user', permissions: ['console.view'] };
}

function fromFormMapping(mapping: FormMapping): ExternalMapping | null {
  if (!mapping?.enabled) return null;
  return { role: mapping.role, permissions: mapping.role === 'admin' ? [] : mapping.permissions };
}

function cleanMappingPermissions<T extends ExternalMapping>(mappings: T[] | undefined): T[] {
  return (mappings ?? []).map((mapping) => ({
    ...mapping,
    permissions: mapping.role === 'admin' ? [] : (mapping.permissions ?? [])
  }));
}

function toFormValues(config: ExternalAuthConfig): FormValues {
  return {
    order: config.order?.length ? config.order : ['tacacs', 'ldap'],
    sessionHours: Math.max(1, Math.round((config.sessionDuration || 28800) / 360) / 10),
    ldap: {
      ...config.ldap,
      urls: config.ldap.urls ?? [],
      groupMappings: cleanMappingPermissions(config.ldap.groupMappings),
      bindPassword: '',
      defaultMapping: toFormMapping(config.ldap.defaultMapping)
    },
    tacacs: {
      ...config.tacacs,
      servers: config.tacacs.servers ?? [],
      privLvlMappings: cleanMappingPermissions(config.tacacs.privLvlMappings),
      secret: '',
      defaultMapping: toFormMapping(config.tacacs.defaultMapping)
    }
  };
}

function toConfig(values: FormValues): ExternalAuthConfig {
  const order = (values.order as unknown as string | AccountSource[]) ?? 'tacacs,ldap';
  return {
    order: (Array.isArray(order) ? order : order.split(',')) as AccountSource[],
    sessionDuration: Math.round((values.sessionHours || 8) * 3600),
    ldap: {
      ...values.ldap,
      urls: (values.ldap.urls ?? []).map((url) => url.trim()).filter(Boolean),
      groupMappings: cleanMappingPermissions(values.ldap.groupMappings),
      defaultMapping: fromFormMapping(values.ldap.defaultMapping)
    },
    tacacs: {
      ...values.tacacs,
      servers: (values.tacacs.servers ?? []).map((server) => server.trim()).filter(Boolean),
      privLvlMappings: cleanMappingPermissions(values.tacacs.privLvlMappings).map((mapping) => ({
        ...mapping,
        minPrivLvl: Number(mapping.minPrivLvl) || 0
      })),
      defaultMapping: fromFormMapping(values.tacacs.defaultMapping)
    }
  };
}

export const ExternalAuth = () => {
  const { t } = useTranslation();
  const [messageApi, contextHolder] = message.useMessage();
  const [form] = Form.useForm<FormValues>();
  const [testForm] = Form.useForm<TestValues>();

  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [isTesting, setIsTesting] = useState(false);
  const [loadError, setLoadError] = useState('');
  const [hasBindPassword, setHasBindPassword] = useState(false);
  const [hasSecret, setHasSecret] = useState(false);
  const [catalog, setCatalog] = useState<PermissionDescriptor[]>([]);
  const [testResult, setTestResult] = useState<ExternalAuthTestResult | null>(null);

  const permissionOptions = catalog.map((descriptor) => ({
    value: descriptor.id,
    label: t(permissionLabelKey(descriptor.id))
  }));
  const roleOptions = [
    { value: 'admin', label: t('settings.account.roles.admin') },
    { value: 'user', label: t('settings.account.roles.user') }
  ];

  function applySettings(settings: api.ExternalAuthSettings) {
    form.setFieldsValue(toFormValues(settings.config));
    setHasBindPassword(settings.hasBindPassword);
    setHasSecret(settings.hasSecret);
    setLoadError(settings.loadError ?? '');
  }

  useEffect(() => {
    api
      .getExternalAuth()
      .then((rsp) => {
        if (rsp.code !== 0) throw new Error(rsp.msg);
        applySettings(rsp.data);
      })
      .catch(() => messageApi.error(t('settings.externalAuth.loadFailed')))
      .finally(() => setIsLoading(false));
    api
      .getPermissions()
      .then((rsp) => {
        if (rsp.code === 0 && Array.isArray(rsp.data?.permissions)) {
          setCatalog(rsp.data.permissions);
        }
      })
      .catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function save() {
    let values: FormValues;
    try {
      values = await form.validateFields();
    } catch {
      return;
    }
    setIsSaving(true);
    try {
      const rsp = await api.setExternalAuth(toConfig(values));
      if (rsp.code !== 0) {
        messageApi.error(`${t('settings.externalAuth.saveFailed')} — ${rsp.msg}`);
        return;
      }
      applySettings(rsp.data);
      messageApi.success(t('settings.externalAuth.saved'));
    } catch {
      messageApi.error(t('settings.externalAuth.saveFailed'));
    } finally {
      setIsSaving(false);
    }
  }

  async function runTest(values: TestValues) {
    setIsTesting(true);
    setTestResult(null);
    try {
      const config = toConfig(form.getFieldsValue(true));
      // The test checks one directory even while it is switched off, so the
      // settings can be tried before they are enabled.
      config[values.source].enabled = true;
      const rsp = await api.testExternalAuth(
        values.source,
        values.username,
        encrypt(values.password),
        config
      );
      if (rsp.code !== 0) {
        setTestResult({ success: false, error: rsp.msg });
        return;
      }
      setTestResult(rsp.data);
    } catch {
      setTestResult({ success: false, error: t('settings.externalAuth.testRequestFailed') });
    } finally {
      setIsTesting(false);
    }
  }

  return (
    <>
      {contextHolder}
      <div className="text-base">{t('settings.externalAuth.title')}</div>
      <Divider className="opacity-50" />

      <div className="mb-4 text-sm text-neutral-400">{t('settings.externalAuth.description')}</div>
      {loadError && (
        <Alert
          className="mb-4"
          type="error"
          showIcon
          message={t('settings.externalAuth.loadErrorTitle')}
          description={loadError}
        />
      )}

      <Form<FormValues> form={form} layout="vertical" disabled={isLoading || isSaving}>
        <div className="grid grid-cols-1 gap-x-4 sm:grid-cols-2">
          <Form.Item
            label={t('settings.externalAuth.order')}
            name="order"
            getValueProps={(value: AccountSource[] | string) => ({
              value: Array.isArray(value) ? value.join(',') : value
            })}
            normalize={(value: string) => value.split(',')}
          >
            <Select options={ORDER_OPTIONS} />
          </Form.Item>
          <Form.Item
            label={t('settings.externalAuth.sessionHours')}
            name="sessionHours"
            tooltip={t('settings.externalAuth.sessionHoursHint')}
            rules={[{ required: true }]}
          >
            <InputNumber min={0.1} max={744} step={1} className="w-full" />
          </Form.Item>
        </div>

        <Tabs
          items={[
            {
              key: 'ldap',
              label: 'LDAP / Active Directory',
              forceRender: true,
              children: (
                <LDAPSection
                  hasBindPassword={hasBindPassword}
                  roleOptions={roleOptions}
                  permissionOptions={permissionOptions}
                  form={form}
                />
              )
            },
            {
              key: 'tacacs',
              label: 'TACACS+',
              forceRender: true,
              children: (
                <TACACSSection
                  hasSecret={hasSecret}
                  roleOptions={roleOptions}
                  permissionOptions={permissionOptions}
                  form={form}
                />
              )
            }
          ]}
        />

        <Button type="primary" className="mt-2 w-full" loading={isSaving} onClick={save}>
          {t('settings.externalAuth.save')}
        </Button>
      </Form>

      <Divider className="opacity-50" />

      <div className="mb-2 text-base">{t('settings.externalAuth.testTitle')}</div>
      <div className="mb-4 text-sm text-neutral-400">{t('settings.externalAuth.testHint')}</div>
      <Form<TestValues>
        form={testForm}
        layout="vertical"
        initialValues={{ source: 'ldap' }}
        onFinish={runTest}
        disabled={isLoading}
      >
        <div className="grid grid-cols-1 gap-x-4 sm:grid-cols-3">
          <Form.Item name="source" label={t('settings.externalAuth.testSource')}>
            <Select
              options={[
                { value: 'ldap', label: 'LDAP' },
                { value: 'tacacs', label: 'TACACS+' }
              ]}
            />
          </Form.Item>
          <Form.Item
            name="username"
            label={t('auth.placeholderUsername')}
            rules={[{ required: true, message: t('auth.noEmptyUsername') }]}
          >
            <Input autoComplete="off" />
          </Form.Item>
          <Form.Item
            name="password"
            label={t('auth.placeholderPassword')}
            rules={[{ required: true, message: t('auth.noEmptyPassword') }]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
        </div>
        <Button htmlType="submit" loading={isTesting} className="w-full">
          {t('settings.externalAuth.testBtn')}
        </Button>
      </Form>

      {testResult && (
        <Alert
          className="mt-4"
          type={testResult.success ? 'success' : testResult.unavailable ? 'warning' : 'error'}
          showIcon
          message={
            testResult.success
              ? t('settings.externalAuth.testSuccess', {
                  username: testResult.username,
                  role: t(`settings.account.roles.${testResult.role}`)
                })
              : t('settings.externalAuth.testFailed')
          }
          description={
            testResult.success ? (
              <div className="flex flex-col gap-1">
                {testResult.role === 'user' && (
                  <div className="flex flex-wrap gap-1">
                    {(testResult.permissions ?? []).length === 0 ? (
                      <span>{t('settings.externalAuth.noPermissions')}</span>
                    ) : (
                      (testResult.permissions ?? []).map((permission) => (
                        <Tag key={permission}>{t(permissionLabelKey(permission))}</Tag>
                      ))
                    )}
                  </div>
                )}
                {(testResult.details ?? []).map((detail) => (
                  <div key={detail} className="break-all text-xs text-neutral-400">
                    {detail}
                  </div>
                ))}
              </div>
            ) : (
              <span className="break-all">{testResult.error}</span>
            )
          }
        />
      )}
    </>
  );
};

type Option = { value: string; label: string };

type SectionProps = {
  roleOptions: Option[];
  permissionOptions: Option[];
  form: FormInstance<FormValues>;
};

// MappingFields renders role and grants for one rule; grants only apply to the
// user role, administrators hold everything.
const MappingFields = ({
  name,
  listPath,
  roleOptions,
  permissionOptions,
  form
}: SectionProps & { name: (string | number)[]; listPath: (string | number)[] }) => {
  const { t } = useTranslation();
  const role = Form.useWatch([...listPath, ...name, 'role'], form);
  return (
    <>
      <Form.Item
        name={[...name, 'role']}
        className="mb-2 w-36 shrink-0"
        rules={[{ required: true }]}
      >
        <Select options={roleOptions} />
      </Form.Item>
      {role !== 'admin' && (
        <Form.Item name={[...name, 'permissions']} className="mb-2 min-w-0 flex-1">
          <Select
            mode="multiple"
            options={permissionOptions}
            placeholder={t('settings.externalAuth.permissions')}
            maxTagCount="responsive"
          />
        </Form.Item>
      )}
    </>
  );
};

const DefaultMappingFields = ({
  section,
  roleOptions,
  permissionOptions,
  form
}: SectionProps & { section: 'ldap' | 'tacacs' }) => {
  const { t } = useTranslation();
  const enabled = Form.useWatch([section, 'defaultMapping', 'enabled'], form);
  return (
    <div className="mt-2">
      <Form.Item
        name={[section, 'defaultMapping', 'enabled']}
        valuePropName="checked"
        label={t('settings.externalAuth.defaultMapping')}
        tooltip={t('settings.externalAuth.defaultMappingHint')}
        className="mb-2"
      >
        <Switch />
      </Form.Item>
      {enabled && (
        <div className="flex gap-2">
          <MappingFields
            name={['defaultMapping']}
            listPath={[section]}
            roleOptions={roleOptions}
            permissionOptions={permissionOptions}
            form={form}
          />
        </div>
      )}
    </div>
  );
};

const LDAPSection = ({
  hasBindPassword,
  ...props
}: SectionProps & { hasBindPassword: boolean }) => {
  const { t } = useTranslation();
  return (
    <>
      <Form.Item
        name={['ldap', 'enabled']}
        valuePropName="checked"
        label={t('settings.externalAuth.enabled')}
      >
        <Switch />
      </Form.Item>
      <Form.Item
        name={['ldap', 'urls']}
        label={t('settings.externalAuth.ldap.urls')}
        tooltip={t('settings.externalAuth.ldap.urlsHint')}
      >
        <Select
          mode="tags"
          open={false}
          tokenSeparators={[' ', ',']}
          placeholder="ldaps://dc1.example.com:636"
        />
      </Form.Item>
      <div className="grid grid-cols-1 gap-x-4 sm:grid-cols-3">
        <Form.Item name={['ldap', 'startTLS']} valuePropName="checked" label="StartTLS">
          <Switch />
        </Form.Item>
        <Form.Item
          name={['ldap', 'insecureSkipVerify']}
          valuePropName="checked"
          label={t('settings.externalAuth.ldap.insecureSkipVerify')}
          tooltip={t('settings.externalAuth.ldap.insecureSkipVerifyHint')}
        >
          <Switch />
        </Form.Item>
        <Form.Item name={['ldap', 'timeout']} label={t('settings.externalAuth.timeout')}>
          <InputNumber min={1} max={60} className="w-full" />
        </Form.Item>
      </div>
      <Form.Item
        name={['ldap', 'caFile']}
        label={t('settings.externalAuth.ldap.caFile')}
        tooltip={t('settings.externalAuth.ldap.caFileHint')}
      >
        <Input placeholder="/etc/kvm/ldap-ca.pem" />
      </Form.Item>
      <Form.Item
        name={['ldap', 'bindDN']}
        label={t('settings.externalAuth.ldap.bindDN')}
        tooltip={t('settings.externalAuth.ldap.bindDNHint')}
      >
        <Input placeholder="CN=svc-kvm,OU=Service,DC=example,DC=com" autoComplete="off" />
      </Form.Item>
      <Form.Item
        name={['ldap', 'bindPassword']}
        label={t('settings.externalAuth.ldap.bindPassword')}
      >
        <Input.Password
          autoComplete="new-password"
          placeholder={hasBindPassword ? t('settings.externalAuth.secretStored') : ''}
        />
      </Form.Item>
      <Form.Item name={['ldap', 'baseDN']} label="Base DN">
        <Input placeholder="DC=example,DC=com" />
      </Form.Item>
      <Form.Item
        name={['ldap', 'userFilter']}
        label={t('settings.externalAuth.ldap.userFilter')}
        tooltip={t('settings.externalAuth.ldap.userFilterHint')}
      >
        <Input placeholder="(&(objectClass=user)(sAMAccountName=%s))" />
      </Form.Item>
      <div className="grid grid-cols-1 gap-x-4 sm:grid-cols-2">
        <Form.Item
          name={['ldap', 'groupAttribute']}
          label={t('settings.externalAuth.ldap.groupAttribute')}
        >
          <Input placeholder="memberOf" />
        </Form.Item>
        <Form.Item
          name={['ldap', 'groupSearchFilter']}
          label={t('settings.externalAuth.ldap.groupSearchFilter')}
          tooltip={t('settings.externalAuth.ldap.groupSearchFilterHint')}
        >
          <Input placeholder="(&(objectClass=posixGroup)(memberUid=%u))" />
        </Form.Item>
      </div>

      <div className="mb-2 mt-2">{t('settings.externalAuth.ldap.groupMappings')}</div>
      <div className="mb-2 text-xs text-neutral-400">
        {t('settings.externalAuth.ldap.groupMappingsHint')}
      </div>
      <Form.List name={['ldap', 'groupMappings']}>
        {(fields, { add, remove }) => (
          <>
            {fields.map((field) => (
              <div key={field.key} className="flex flex-wrap items-start gap-2">
                <Form.Item
                  name={[field.name, 'group']}
                  className="mb-2 w-full sm:w-auto sm:flex-[2]"
                  rules={[{ required: true, message: t('settings.externalAuth.required') }]}
                >
                  <Input placeholder="CN=KVM-Admins,OU=Groups,DC=example,DC=com" />
                </Form.Item>
                <MappingFields
                  {...props}
                  name={[field.name]}
                  listPath={['ldap', 'groupMappings']}
                />
                <Button
                  danger
                  icon={<Trash2Icon size={14} />}
                  onClick={() => remove(field.name)}
                  aria-label={t('settings.account.users.delete')}
                />
              </div>
            ))}
            <Button
              icon={<PlusIcon size={14} />}
              onClick={() => add({ group: '', role: 'user', permissions: ['console.view'] })}
            >
              {t('settings.externalAuth.addMapping')}
            </Button>
          </>
        )}
      </Form.List>
      <DefaultMappingFields {...props} section="ldap" />
    </>
  );
};

const TACACSSection = ({ hasSecret, ...props }: SectionProps & { hasSecret: boolean }) => {
  const { t } = useTranslation();
  return (
    <>
      <Form.Item
        name={['tacacs', 'enabled']}
        valuePropName="checked"
        label={t('settings.externalAuth.enabled')}
      >
        <Switch />
      </Form.Item>
      <Form.Item
        name={['tacacs', 'servers']}
        label={t('settings.externalAuth.tacacs.servers')}
        tooltip={t('settings.externalAuth.tacacs.serversHint')}
      >
        <Select mode="tags" open={false} tokenSeparators={[' ', ',']} placeholder="10.0.0.5:49" />
      </Form.Item>
      <Form.Item name={['tacacs', 'secret']} label={t('settings.externalAuth.tacacs.secret')}>
        <Input.Password
          autoComplete="new-password"
          placeholder={hasSecret ? t('settings.externalAuth.secretStored') : ''}
        />
      </Form.Item>
      <div className="grid grid-cols-1 gap-x-4 sm:grid-cols-3">
        <Form.Item
          name={['tacacs', 'authenType']}
          label={t('settings.externalAuth.tacacs.authenType')}
        >
          <Select
            options={[
              { value: 'pap', label: 'PAP' },
              { value: 'ascii', label: 'ASCII' }
            ]}
          />
        </Form.Item>
        <Form.Item
          name={['tacacs', 'service']}
          label={t('settings.externalAuth.tacacs.service')}
          tooltip={t('settings.externalAuth.tacacs.serviceHint')}
        >
          <Input placeholder="nanokvm" />
        </Form.Item>
        <Form.Item name={['tacacs', 'timeout']} label={t('settings.externalAuth.timeout')}>
          <InputNumber min={1} max={60} className="w-full" />
        </Form.Item>
      </div>
      <div className="grid grid-cols-1 gap-x-4 sm:grid-cols-2">
        <Form.Item
          name={['tacacs', 'roleAttribute']}
          label={t('settings.externalAuth.tacacs.roleAttribute')}
          tooltip={t('settings.externalAuth.tacacs.roleAttributeHint')}
        >
          <Input placeholder="nanokvm-role" />
        </Form.Item>
        <Form.Item
          name={['tacacs', 'permissionsAttribute']}
          label={t('settings.externalAuth.tacacs.permissionsAttribute')}
          tooltip={t('settings.externalAuth.tacacs.permissionsAttributeHint')}
        >
          <Input placeholder="nanokvm-perms" />
        </Form.Item>
      </div>

      <div className="mb-2 mt-2">{t('settings.externalAuth.tacacs.privLvlMappings')}</div>
      <div className="mb-2 text-xs text-neutral-400">
        {t('settings.externalAuth.tacacs.privLvlMappingsHint')}
      </div>
      <Form.List name={['tacacs', 'privLvlMappings']}>
        {(fields, { add, remove }) => (
          <>
            {fields.map((field) => (
              <div key={field.key} className="flex flex-wrap items-start gap-2">
                <Form.Item name={[field.name, 'minPrivLvl']} className="mb-2 w-24 shrink-0">
                  <InputNumber min={0} max={15} addonBefore="≥" className="w-full" />
                </Form.Item>
                <MappingFields
                  {...props}
                  name={[field.name]}
                  listPath={['tacacs', 'privLvlMappings']}
                />
                <Button
                  danger
                  icon={<Trash2Icon size={14} />}
                  onClick={() => remove(field.name)}
                  aria-label={t('settings.account.users.delete')}
                />
              </div>
            ))}
            <Button
              icon={<PlusIcon size={14} />}
              onClick={() => add({ minPrivLvl: 15, role: 'admin', permissions: [] })}
            >
              {t('settings.externalAuth.addMapping')}
            </Button>
          </>
        )}
      </Form.List>
      <DefaultMappingFields {...props} section="tacacs" />
    </>
  );
};
