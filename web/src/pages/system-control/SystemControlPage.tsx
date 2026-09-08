import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Alert, App as AntdApp, Button, Card, Space, Typography } from 'antd'
import { PoweroffOutlined, ReloadOutlined, WarningOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { FACTORY_RESET_CONFIRM_TEXT, systemOpsApi } from '../../api/systemOps'
import PasswordConfirmModal from '../../components/PasswordConfirmModal'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'

type OpKind = 'reboot' | 'shutdown' | 'factory_reset'

const OP_META: Record<
  OpKind,
  {
    title: string
    description: string
    buttonText: string
    modalTitle: string
    riskContent: string
    successMessage: string
    permission: string
  }
> = {
  reboot: {
    title: '系统重启',
    description: '重启管理设备操作系统，重启期间管理控制台与防护服务将中断数分钟。',
    buttonText: '立即重启',
    modalTitle: '高风险操作确认：系统重启',
    riskContent: '重启期间管理控制台与防护服务将中断数分钟，业务流量可能受到影响。请输入当前账号密码以确认执行重启。',
    successMessage: '重启指令已受理，设备即将重启，请稍后再访问管理控制台',
    permission: 'system.reboot',
  },
  shutdown: {
    title: '系统关机',
    description: '关闭管理设备电源，关机后需到现场重新开机。',
    buttonText: '立即关机',
    modalTitle: '高风险操作确认：系统关机',
    riskContent: '关机后管理控制台与防护服务将完全停止，需到现场重新开机才能恢复。请输入当前账号密码以确认执行关机。',
    successMessage: '关机指令已受理，设备即将关机，请到现场重新开机后再访问',
    permission: 'system.shutdown',
  },
  factory_reset: {
    title: '恢复出厂设置',
    description: '清空全部业务数据、用户账号、授权与配置，恢复到初始安装状态，此操作不可撤销。',
    buttonText: '恢复出厂设置',
    modalTitle: '高风险操作确认：恢复出厂设置',
    riskContent: '将清空全部业务数据、用户账号、授权与配置，恢复到初始安装状态，此操作不可撤销！请输入确认文字与当前账号密码。',
    successMessage: '系统将恢复到初始安装状态，请使用初始管理员账号重新登录并重新导入授权',
    permission: 'system.factory_reset',
  },
}

function OperationCard({ kind }: { kind: OpKind }) {
  const { message, modal } = AntdApp.useApp()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const meta = OP_META[kind]
  const [confirmOpen, setConfirmOpen] = useState(false)

  const opMutation = useMutation({
    mutationFn: (password: string) => {
      if (kind === 'reboot') return systemOpsApi.reboot(password)
      if (kind === 'shutdown') return systemOpsApi.shutdown(password)
      return systemOpsApi.factoryReset(password, FACTORY_RESET_CONFIRM_TEXT)
    },
    onSuccess: () => {
      setConfirmOpen(false)
      message.success(meta.successMessage)
      if (kind !== 'factory_reset') {
        modal.success({
          title: '指令已受理',
          content: '设备即将执行操作，管理控制台将暂时不可用，请稍后再访问。',
        })
      }
    },
    onError: (e: unknown) => {
      message.error(e instanceof ApiError ? e.message : '操作失败')
    },
  })

  if (!hasPermission(permissions, meta.permission)) return null

  return (
    <>
      <Card type="inner" title={meta.title}>
        <Space direction="vertical" size={12}>
          <Typography.Text type="secondary">{meta.description}</Typography.Text>
          <div>
            <Button
              danger
              icon={kind === 'reboot' ? <ReloadOutlined /> : kind === 'shutdown' ? <PoweroffOutlined /> : <WarningOutlined />}
              onClick={() => setConfirmOpen(true)}
            >
              {meta.buttonText}
            </Button>
          </div>
        </Space>
      </Card>
      <PasswordConfirmModal
        open={confirmOpen}
        title={meta.modalTitle}
        content={meta.riskContent}
        confirmText={kind === 'factory_reset' ? FACTORY_RESET_CONFIRM_TEXT : undefined}
        loading={opMutation.isPending}
        onOk={(password) => opMutation.mutate(password)}
        onCancel={() => setConfirmOpen(false)}
      />
    </>
  )
}

/** 系统控制：系统重启 / 系统关机 / 恢复出厂设置（均为高风险操作，需密码二次确认） */
export default function SystemControlPage() {
  return (
    <Card title="系统控制">
      <Alert
        type="warning"
        showIcon
        message="以下操作均为高风险操作"
        description="执行后系统将重启、关机或清空全部数据，请确认已做好备份与现场运维安排后再操作。"
        style={{ marginBottom: 16 }}
      />
      <Space direction="vertical" size={16} style={{ display: 'flex' }}>
        <OperationCard kind="reboot" />
        <OperationCard kind="shutdown" />
        <OperationCard kind="factory_reset" />
      </Space>
    </Card>
  )
}
