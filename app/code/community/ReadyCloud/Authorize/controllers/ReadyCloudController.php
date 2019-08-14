<?php

class ReadyCloud_Authorize_ReadyCloudController extends Mage_Core_Controller_Front_Action
{
    const TITLE = 'ReadyCloud';
    const EMAIL = 'email@readycloud.com';
    const CALLBACK_URL = 'http://263c9dbe.ngrok.com/call_back';

    /**
     * Create the SOAP user
     * @param $role_id
     * @return array - SOAP login and SOAP password
     */
    private function createSoapUser($role_id)
    {
        $apiLogin = Mage::helper('core')->getRandomString(32);
        $apiPass = Mage::helper('core')->getRandomString(32);

        $m = Mage::getModel('api/user')
            ->getCollection()
            ->addFieldToFilter('email', self::EMAIL)
            ->getFirstItem();

        if (!$m->isEmpty()) {
            $m->setUsername($apiLogin);
            $m->setApiKey($apiPass);
            $m->save();
            return array(
                'api_login' => $apiLogin,
                'api_pass' => $apiPass
            );
        }

        $userapi = Mage::getModel('api/user')
            ->setData(array(
                'username' => $apiLogin,
                'firstname' => self::TITLE,
                'lastname' => self::TITLE,
                'email' => self::EMAIL,
                'api_key' => $apiPass,
                'api_key_confirmation' => $apiPass,
                'is_active' => 1,
                'user_roles' => '',
                'assigned_user_role' => '',
                'role_name' => self::TITLE,
                'roles' => array($role_id)
            ));
        $userapi->save();
        $userapi->setRoleIds(array($role_id))
            ->setRoleUserId($userapi->getUserId())
            ->saveRelations();
        return array(
            'api_login' => $apiLogin,
            'api_pass' => $apiPass
        );
    }

    /**
     * Create the SOAP role and set important values for access
     * @return - SOAP role id
     */
    private function createSoapRole()
    {
        $role = Mage::getModel('api/roles')
            ->getCollection()
            ->addFieldToFilter('role_name', self::TITLE)
            ->getFirstItem();
        if ($role->isEmpty()) {
            $role = Mage::getModel('api/roles')
                ->setName(self::TITLE)
                ->setPid(false)
                ->setRoleType('G')
                ->save();
        }
        Mage::getModel("api/rules")
            ->setRoleId($role->getId())
            ->setResources(array('all'))
            ->saveRel();

        return $role->getId();
    }

    /**
     * Create the new consumer if not exists and return the ID
     * @return - return REST consumer ID
     */
    private function getRestConsumerId()
    {
        $consumer = Mage::getModel('oauth/consumer')
            ->getCollection()
            ->addFieldToFilter('name', self::TITLE)
            ->getFirstItem();
        if (!$consumer->isEmpty())
            return $consumer->getId();

        $model = Mage::getModel('oauth/consumer');
        $helper = Mage::helper('oauth');
        $model->setName(self::TITLE);
        $model->setKey($helper->generateConsumerKey());
        $model->setSecret($helper->generateConsumerSecret());
        $model->save();
        return $model->getId();
    }


    /**
     * Create the auth token if not exists and return the ID
     * @param $consumer_id - consumer ID
     * @return int - consumer ID
     */
    private function getRestTokenIdByConsumerId($consumer_id)
    {
        $token = Mage::getModel('oauth/token')
            ->getCollection()
            ->addFieldToFilter('consumer_id', $consumer_id)
            ->getFirstItem();
        if (!$token->isEmpty())
            return $token->getId();

        // create oauth token
        $m = Mage::getModel('oauth/token');
        $m->createRequestToken($consumer_id, 'oob');
        $m->convertToAccess();

        $admin_id = Mage::getModel('admin/user')->getCollection()->getFirstItem()->getId();
        $m->authorize($admin_id, 'admin');

        $token_id = $m->getId();
        return $token_id;
    }


    /**
     * Create the REST role if not exists and return the ID
     * @return int - REST role ID
     */
    private function createRestRole()
    {
        $m = Mage::getModel('api2/acl_global_role')
            ->getCollection()
            ->addFieldToFilter('role_name', self::TITLE)
            ->getFirstItem();

        if (!$m->isEmpty())
            return $m->getId();

        Mage::getModel('api2/acl_global_role')
            ->setRoleName(self::TITLE)
            ->save();
    }

    /**
     * Create the REST rule if not exists and add the role
     * @param $role_id - REST role ID
     */
    private function createRestRule($role_id)
    {
        $rule = Mage::getModel('api2/acl_global_rule');

        $m = $rule->getCollection()
            ->addFieldToFilter('role_id', $role_id)
            ->getFirstItem();
        if ($m->isEmpty()) {
            $rule->setRoleId($role_id)
                ->setResourceId('all')
                ->setPrivilege(null)
                ->save();
        }
        $this->addUserToRole($role_id);
    }


    /**
     * Add user to the REST role
     * @param $role_id - REST role ID
     */
    private function addUserToRole($role_id)
    {
        $admin_id = Mage::getModel('admin/user')->getCollection()->getFirstItem()->getId();
        $resourceModel = Mage::getResourceModel('api2/acl_global_role');
        $resourceModel->saveAdminToRoleRelation($admin_id, $role_id);
    }

    /**
     * Create REST API keys
     * @return array - keys and access tokens
     */
    private function createRestApiKeys()
    {
        $role_id = $this->createRestRole();
        $this->createRestRule($role_id);

        // create new or get existing consumer and token
        $consumer_id = $this->getRestConsumerId();
        $token_id = $this->getRestTokenIdByConsumerId($consumer_id);

        $consumer = Mage::getModel('oauth/consumer')->load($consumer_id)->getData();
        $token = Mage::getModel('oauth/token')->load($token_id)->getData();

        return array(
            'key' => $consumer['key'],
            'secret' => $consumer['secret'],
            'token' => $token['token'],
            'token_secret' => $token['secret']
        );
    }

    /**
     * Create the SOAP keys and return the ID
     * @return int - role ID
     */
    private function createSoapKeys()
    {
        $role_id = $this->createSoapRole();
        return $this->createSoapUser($role_id);
    }

    /**
     * Return HTTP request with an appropriate status code based on $success argument
     * @param $success - boolean value
     */
    private function printSuccessResponse($success)
    {
        $this->getResponse()
            ->clearHeaders()
            ->setHttpResponseCode(($success)? 200 : 400)
            ->setHeader('Content-Type', 'application/json; charset=utf-8')
            ->setBody(json_encode(array('success' => $success)));
    }

    /**
     * Basic Controller to create the new keys for the user by received uuid
     */
    public function postAction()
    {
        if ($this->getRequest()->isPost()) {
            $uuid = $this->getRequest()->getPost('uuid');

            // access to additional functionality
            Mage::app()->setCurrentStore(Mage_Core_Model_App::ADMIN_STORE_ID);

            $data = array(
                'rest_keys' => $this->createRestApiKeys(),
                'soap_keys' => $this->createSoapKeys()
            );

            $this->callBack($uuid, $data);
        } else {
            $this->printSuccessResponse(false);
        }
    }


    /**
     * Send keys to ReadyCloud
     * @param $uuid - ReadyCloud user unique ID
     * @param $data - REST and SOAP keys
     */
    private function callBack($uuid, $data)
    {
        $data['uuid'] = $uuid;
        $data = json_encode($data);

        ob_start();
        $ch = curl_init(self::CALLBACK_URL);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
        $sent = curl_exec($ch);
        ob_end_clean();

        if ($sent) {
            Mage::log('success: sending keys to ' . self::CALLBACK_URL, null, 'readycloud.log');
        } else {
            Mage::log('***FAIL: when sending data to ' . self::CALLBACK_URL . "\t" .
                curl_error ( $ch ) . "\t" .
                null, 'readycloud.log');
        }
        $this->printSuccessResponse($sent);
    }


    /**
     * Controller to check if this extension has installed
     */
    public function checkAction()
    {
        if ($this->getRequest()->isPost()) {
            $request = $this->getRequest()->getPost('verify');
            if ($request == 'readycloud') {
                $this->printSuccessResponse(true);
            } else {
                $this->printSuccessResponse(false);
            }
        }
    }
}
