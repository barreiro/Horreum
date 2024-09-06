import {useContext, useEffect, useState} from "react"
import {
    Button,
    ClipboardCopy,
    Form,
    FormGroup,
    HelperText,
    HelperTextItem,
    Label,
    Modal,
    TextInput,
    Tooltip,
} from "@patternfly/react-core"

import {ApiKeyResponse, userApi} from "../../api";
import {AppContext} from "../../context/appContext";
import {AppContextType} from "../../context/@types/appContextTypes";
import {ActionsColumn, Table, Tbody, Td, Th, Thead, Tr} from "@patternfly/react-table";

export default function ApiKeys() {
    const {alerting} = useContext(AppContext) as AppContextType;

    const daysAfter = (other: Date) => Math.floor((Date.now() - other.getTime()) / (24 * 3600 * 1000))

    const [apiKeys, setApiKeys] = useState<ApiKeyResponse[]>([])
    const refreshApiKeys = () => userApi.apiKeys().then(
        keys => setApiKeys(keys),
        error => alerting.dispatchError(error, "FETCH_API_KEYS", "Failed to fetch API keys for user")
    )

    const [createApiKey, setCreateApiKey] = useState(false)
    const [newKeyName, setNewKeyName] = useState<string>()
    const [newKeyValue, setNewKeyValue] = useState<string>()

    const [renameKeyId, setRenameKeyId] = useState<number>()
    const [renameKeyName, setRenameKeyName] = useState<string>()

    const keyTypeTooltip = (key: ApiKeyResponse) => {
        switch (key.type) {
            case "USER":
                return "This key provides the same set of permissions this user has";
            default:
                return "Unknown"
        }
    }

    const keyCreationTooltip = (key: ApiKeyResponse) => {
        if (!key.creation) {
            return ""
        } else {
            const d = daysAfter(key.creation)
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
            const d = daysAfter(key.access)
            if (d == 0) {
                return "API key was last used today"
            } else if (d == 1) {
                return "API key was last used yesterday"
            } else {
                return `API key was last used ${d} days ago`
            }
        }
    }

    const keyStatus = (key: ApiKeyResponse) => {
        const labels = [];
        if (key.isExpired) {
            labels.push(<Label color="grey">Expired</Label>)
        } else if (key.isRevoked) {
            labels.push(<Label color="red">Revoked</Label>)
        } else {
            labels.push(<Label color="green">Valid</Label>)
        }
        if (key.expiration != null) {
            if (key.expiration < 1) {
                labels.push(<Label color="orange">Expires TODAY</Label>)
            } else if (key.expiration < 2) {
                labels.push(<Label color="orange">Expires TOMORROW</Label>)
            } else if (key.expiration < 7) {
                labels.push(<Label color="gold">Expires in less than a week</Label>)
            }
        }
        return labels
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
                        <Th label="name" textCenter>Type</Th>
                        <Th label="creation" textCenter>Creation date</Th>
                        <Th label="access" textCenter>Last usage</Th>
                        <Th label="status" textCenter>Status</Th>
                    </Tr>
                </Thead>
                <Tbody>
                    {apiKeys.map((key, i) => (
                        <Tr key={`key-${i}`}>
                            <Td dataLabel="name">{key.name}</Td>
                            <Td dataLabel="type" textCenter>
                                <Tooltip trigger="mouseenter" content={keyTypeTooltip(key)} isVisible={key.type != null}>
                                    <span>{key.type}</span>
                                </Tooltip>
                            </Td>
                            <Td dataLabel="creation" textCenter>
                                <Tooltip trigger="mouseenter" content={keyCreationTooltip(key)}>
                                    <span>{key.creation?.toLocaleDateString() || "undefined"}</span>
                                </Tooltip>
                            </Td>
                            <Td dataLabel="access" textCenter>
                                <Tooltip trigger="mouseenter" content={keyAccessTooltip(key)} isVisible={key.access != null}>
                                    <span>{key.access?.toLocaleDateString() || <Label color="cyan">Never used</Label>}</span>
                                </Tooltip>
                            </Td>
                            <Td dataLabel="status" textCenter>{keyStatus(key)}</Td>
                            <Td isActionCell>
                                <ActionsColumn items={[
                                    {
                                        title: 'Rename',
                                        onClick: () => {
                                            setRenameKeyId(key.id)
                                        }
                                    },
                                    {
                                        title: 'Revoke',
                                        isDisabled: key.isRevoked,
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
                isOpen={createApiKey}
                title="Create new API key"
                aria-label="create-api-key"
                variant="small"
                onClose={() => setCreateApiKey(false)}
                actions={[
                    <Button
                        onClick={() => {
                            userApi.newApiKey({
                                name: newKeyName,
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
                    <Button variant="secondary" onClick={() => setCreateApiKey(false)}>Cancel</Button>,
                ]}
            >
                <Form isHorizontal>
                    <FormGroup isRequired label="Key name" fieldId="new-api-key-name">
                        <TextInput isRequired onChange={(_, val) => setNewKeyName(val)}/>
                    </FormGroup>
                </Form>
            </Modal>
            <Modal
                isOpen={newKeyValue != undefined}
                title={`New key '${newKeyName}'`}
                aria-label="new-api-key"
                variant="small"
                onClose={() => setNewKeyValue(undefined)}>
                footer={
                <HelperText>
                    <HelperTextItem variant="warning" hasIcon>
                        This is the only time you'll be able to see the key
                    </HelperTextItem>
                </HelperText>
            }
                <ClipboardCopy isReadOnly>{newKeyValue}</ClipboardCopy>
            </Modal>
            <Modal
                isOpen={renameKeyId != undefined}
                title={"Rename API key"}
                aria-label="rename-api-key"
                variant="small"
                onClose={() => setRenameKeyId(undefined)}
                actions={[
                    <Button
                        onClick={() => {
                            if (renameKeyId) {
                                userApi.renameApiKey(renameKeyId, renameKeyName)
                                    .then(() => void alerting.dispatchInfo("API_KEY_RENAMED", "API key renamed", "API key was successfully renamed", 3000))
                                    .catch(error => alerting.dispatchError(error, "API_KEY_NOT_RENAMED", "Failed to rename API key"))
                                    .finally(() => setRenameKeyId(undefined))
                                    .then(() => void refreshApiKeys())
                            }
                        }}
                    >
                        Rename
                    </Button>,
                    <Button variant="secondary" onClick={() => setRenameKeyId(undefined)}>Cancel</Button>,
                ]}>
                <Form isHorizontal>
                    <FormGroup isRequired label="Key name" fieldId="rennew-api-key-name">
                        <TextInput isRequired onChange={(_, val) => setRenameKeyName(val)}/>
                    </FormGroup>
                </Form>
            </Modal>
        </>
    )
}
