import {useContext, useEffect, useState} from "react"
import {
    Button,
    ClipboardCopy,
    DatePicker,
    Form,
    FormGroup,
    HelperText,
    HelperTextItem,
    Label,
    Modal,
    NumberInput,
    TextInput,
    Tooltip,
    yyyyMMddFormat,
} from "@patternfly/react-core"

import {ApiKeyResponse, userApi} from "../../api";
import {AppContext} from "../../context/appContext";
import {AppContextType} from "../../context/@types/appContextTypes";
import {ActionsColumn, Table, Tbody, Td, Th, Thead, Tr} from "@patternfly/react-table";

export default function ApiKeys() {
    const {alerting} = useContext(AppContext) as AppContextType;

    const daysTo = (other: Date) => Math.ceil((other.getTime() - Date.now()) / (24 * 3600 * 1000))
    const defaultExpiration = () => yyyyMMddFormat(new Date(Date.now() + 400 * 24 * 3600 * 1000)) // default 400 days

    const [apiKeys, setApiKeys] = useState<ApiKeyResponse[]>([])
    const refreshApiKeys = () => userApi.apiKeys().then(
        keys => setApiKeys(keys),
        error => alerting.dispatchError(error, "FETCH_API_KEYS", "Failed to fetch API keys for user")
    )

    const [createApiKey, setCreateApiKey] = useState(false)
    const [newKeyName, setNewKeyName] = useState<string>()
    const [newKeyExpiration, setNewKeyExpiration] = useState<string>(defaultExpiration)
    const [newKeyValue, setNewKeyValue] = useState<string>()

    const [renewKeyId, setRenewKeyId] = useState<number>()
    const [renewKeyExpiration, setRenewKeyExpiration] = useState<number>(90)

    const rangeValidator = (date: Date) => {
        const days = daysTo(date);
        if (days < 0) {
            return "Date is before the allowable range";
        } else if (days > 1000) { // max lifetime of the key
            return "Date is after the allowable range";
        }
        return "";
    };

    const resetNewKey = () => {
        setCreateApiKey(false)
        setNewKeyName(undefined)
        setNewKeyExpiration(defaultExpiration())
    }

    const keyTypeTooltip = (key: ApiKeyResponse) => {
        switch (key.type) {
            case "USER":
                return "This key provides the same permissions this user has";
            default:
                return "Unknown"
        }
    }

    const keyCreationTooltip = (key: ApiKeyResponse) => {
        if (!key.creation) {
            return ""
        } else {
            const d = -daysTo(key.creation)
            if (d == 0) {
                return "API key was created today"
            } else {
                return `API key was created ${d} days ago`
            }
        }
    }

    const keyAccessTooltip = (key: ApiKeyResponse) => {
        if (!key.access) {
            return "API key has never been used"
        } else {
            const d = -daysTo(key.access)
            if (d == 0) {
                return "API key was last used today"
            } else {
                return `API key was last used ${d} days ago`
            }
        }
    }

    const keyExpirationTooltip = (key: ApiKeyResponse) => {
        if (key.isRevoked) {
            return "API key has been revoked"
        } else if (key.isExpired) {
            return "API key has expired"
        } else if (key.expiration) {
            const d = daysTo(key.expiration)
            if (d == 0) {
                return "API key expires TODAY!"
            } else {
                return `API key expires in ${d} days`
            }
        }
    }

    const keyStatus = (token: ApiKeyResponse) => {
        if (token.isRevoked) {
            return <Label color="red">Revoked</Label>
        } else if (token.isExpired) {
            return <Label color="grey">Expired</Label>
        } else if (!token.access) {
            return <Label color="cyan">Never used</Label>
        } else if (token.expiration) {
            const d = daysTo(token.expiration)
            if (d < 1) {
                return <Label color="orange">Expires TODAY</Label>
            } else if (d < 2) {
                return <Label color="orange">Expires TOMORROW</Label>
            }
            if (d < 7) {
                return <Label color="gold">Expires in less than a week</Label>
            } else if (d < 30) {
                return <Label color="green">Expires in less than a month</Label>
            }
        }
        return <Label color="green">Valid</Label>
    }


    useEffect(() => {
        void refreshApiKeys();
    }, [])

    return (
        <>
            <Table aria-label="api-keys" isStickyHeader borders={false}>
                <Thead>
                    <Tr>
                        <Th label="name" width={40}>Name</Th>
                        <Th label="name">Type</Th>
                        <Th label="creation">Creation date</Th>
                        <Th label="access">Last usage</Th>
                        <Th label="expiration">Expiration date</Th>
                        <Th label="status">Status</Th>
                    </Tr>
                </Thead>
                <Tbody>
                    {apiKeys.map((key, i) => (
                        <Tr key={`key-${i}`}>
                            <Td dataLabel="name">{key.name}</Td>
                            <Td dataLabel="type">
                                <Tooltip content={keyTypeTooltip(key)} isVisible={key.type != null}>
                                    <span>{key.type}</span>
                                </Tooltip>
                            </Td>
                            <Td dataLabel="creation">
                                <Tooltip content={keyCreationTooltip(key)}>
                                    <span>{key.creation?.toLocaleDateString() || "undefined"}</span>
                                </Tooltip>
                            </Td>
                            <Td dataLabel="access">
                                <Tooltip content={keyAccessTooltip(key)} isVisible={key.access != null}>
                                    <span>{key.access?.toLocaleDateString()}</span>
                                </Tooltip>
                            </Td>
                            <Td dataLabel="expiration">
                                <Tooltip content={keyExpirationTooltip(key)}>
                                    <span>{key.expiration?.toLocaleDateString() || "undefined"}</span>
                                </Tooltip>
                            </Td>
                            <Td dataLabel="status">{keyStatus(key)}</Td>
                            <Td isActionCell>
                                <ActionsColumn items={key.isRevoked ? [] : [
                                    {
                                        title: 'Renew',
                                        isDisabled: !(key.expiration && daysTo(key.expiration) < 7), // only allow to renew in last 7 days
                                        onClick: () => {
                                            setRenewKeyExpiration(90) // default 90 days in the future
                                            setRenewKeyId(key.id)
                                        }
                                    },
                                    {
                                        title: 'Revoke',
                                        onClick: () => {
                                            if (key.id && confirm(`Are you sure you want to revoke API key '${key.name}'?`)) {
                                                userApi.revokeApiKey(key.id).then(
                                                    _ => void refreshApiKeys(),
                                                    error => alerting.dispatchError(error, "REVOKE_API_KEY", "Failed to revoke API key")
                                                )
                                            }
                                        }
                                    }
                                ]}
                                />
                            </Td>
                        </Tr>
                    ))}
                </Tbody>
            </Table>
            <Button onClick={() => setCreateApiKey(true)}>New API key</Button>

            <Modal
                title="Create new API key"
                variant="small"
                isOpen={createApiKey}
                onClose={resetNewKey}
                actions={[
                    <Button
                        onClick={() => {
                            userApi.newApiKey({
                                name: newKeyName,
                                expiration: daysTo(new Date(newKeyExpiration)),
                                type: "USER"
                            })
                                .then((tokenValue) => {
                                    setNewKeyValue(tokenValue)
                                    void alerting.dispatchInfo("API_KEY_CREATED", "API key created", "API key was successfully created", 3000)
                                })
                                .catch(error => alerting.dispatchError(error, "API_KEY_NOT_CREATED", "Failed to create new API key"))
                                .finally(() => setCreateApiKey(false))
                                .then(() => void refreshApiKeys())
                        }}
                    >
                        Create
                    </Button>,
                    <Button variant="secondary" onClick={resetNewKey}>Cancel</Button>,
                ]}
            >
                <Form isHorizontal>
                    <FormGroup isRequired label="Key Name" fieldId="new-api-key-name">
                        <TextInput isRequired value={newKeyName} onChange={(_event, val) => setNewKeyName(val)}/>
                    </FormGroup>
                    <FormGroup label="Expiration date" fieldId="new-api-key-expiration">
                        <DatePicker value={newKeyExpiration}
                                    onChange={(_, date) => setNewKeyExpiration(date)}
                                    validators={[rangeValidator]}/>
                    </FormGroup>
                </Form>
            </Modal>
            <Modal
                isOpen={newKeyValue != undefined}
                title={`New key '${newKeyName}'`}
                footer={
                    <HelperText>
                        <HelperTextItem variant="warning" hasIcon>
                            This is the only time you'll be able to see the key
                        </HelperTextItem>
                    </HelperText>
                }
                aria-label="new-api-key"
                variant="small"
                onClose={() => setNewKeyValue(undefined)}>
                <ClipboardCopy isReadOnly>{newKeyValue}</ClipboardCopy>
            </Modal>
            <Modal
                isOpen={renewKeyId != undefined}
                title={"Renew API key"}
                aria-label="renew-api-key"
                variant="small"
                onClose={() => setNewKeyValue(undefined)}
                actions={[
                    <Button
                        onClick={() => {
                            if (renewKeyId) {
                                userApi.renewApiKey(renewKeyId, renewKeyExpiration)
                                    .then(() => void alerting.dispatchInfo("API_KEY_RENEWED", "API key renewed", "API key was successfully renewed", 3000))
                                    .catch(error => alerting.dispatchError(error, "API_KEY_NOT_RENEWED", "Failed to renew API key"))
                                    .finally(() => setRenewKeyId(undefined))
                                    .then(() => void refreshApiKeys())
                            }
                        }}
                    >
                        Renew
                    </Button>,
                    <Button variant="secondary" onClick={() => setRenewKeyId(undefined)}>Cancel</Button>,
                ]}>
                <Form isHorizontal>
                    <FormGroup isRequired label="Days to expiration" fieldId="renew-api-key-expiration">
                        <NumberInput
                            value={renewKeyExpiration}
                            min={0}
                            max={100}
                            onMinus={() => setRenewKeyExpiration(renewKeyExpiration - 1)}
                            onPlus={() => setRenewKeyExpiration(renewKeyExpiration + 1)}
                            onChange={(event) => {
                                const value = (event.target as HTMLInputElement).value;
                                setRenewKeyExpiration(value === '' ? 0 : +value);
                            }}
                        />
                    </FormGroup>
                </Form>
            </Modal>
        </>
    )
}
