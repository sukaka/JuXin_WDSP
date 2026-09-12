import { Select } from 'antd'
import { useEndpointOptions } from './useEndpointOptions'

/** 端点选择器（过滤与表单共用；受控组件，可直接作为 Form.Item 子控件） */
export default function EndpointSelect({
  value,
  onChange,
  allowClear,
  placeholder,
  disabled,
}: {
  value?: string
  onChange?: (v?: string) => void
  allowClear?: boolean
  placeholder?: string
  disabled?: boolean
}) {
  const { options, isLoading } = useEndpointOptions()
  return (
    <Select
      showSearch
      optionFilterProp="label"
      style={{ width: '100%' }}
      placeholder={placeholder ?? '选择接口'}
      loading={isLoading}
      value={value}
      onChange={onChange}
      allowClear={allowClear}
      disabled={disabled}
      options={options}
    />
  )
}
