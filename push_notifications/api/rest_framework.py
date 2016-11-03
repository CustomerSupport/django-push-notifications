from __future__ import absolute_import
from django.utils import timezone

from rest_framework import permissions
from rest_framework.serializers import Serializer, ModelSerializer, ValidationError
from rest_framework.viewsets import ModelViewSet
from rest_framework.fields import IntegerField, DurationField

from push_notifications.models import APNSDevice, GCMDevice, WNSDevice
from push_notifications.fields import hex_re
from push_notifications.fields import UNSIGNED_64BIT_INT_MAX_VALUE


# Fields


class HexIntegerField(IntegerField):
	"""
	Store an integer represented as a hex string of form "0x01".
	"""

	def to_internal_value(self, data):
		# validate hex string and convert it to the unsigned
		# integer representation for internal use
		try:
			data = int(data, 16) if type(data) != int else data
		except ValueError:
			raise ValidationError("Device ID is not a valid hex number")
		return super(HexIntegerField, self).to_internal_value(data)

	def to_representation(self, value):
		return value


class TimerField(DurationField):
	"""
	Stores an offset from the current time in a DateTimeField.
	Takes input in seconds or DRF's DurationFieldFormat, returns offset in seconds
	If stored DateTime is in the past, return None
	"""
	def to_representation(self, value):
		if value < timezone.now():
			return None
		value = value - timezone.now()
		return value.total_seconds()

	def to_internal_value(self, value):
		val = super().to_internal_value(value)
		return val + timezone.now()


# Serializers
class DeviceSerializerMixin(ModelSerializer):
	mute_for = TimerField(source="muted_till")
	
	class Meta:
		fields = ("id", "name", "registration_id", "device_id", "active", "date_created", "mute_for")
		read_only_fields = ("date_created",)

		# See https://github.com/tomchristie/django-rest-framework/issues/1101
		extra_kwargs = {"active": {"default": True}}


class OverwriteRegistrationSerializerMixin(Serializer):
	"""
	If the registration_id is already in use, delete that device
	If someone were to logout of the app without internet and then log in to a different account
	this makes sure they are able to get notifications
	"""
	def validate(self, attrs):
		devices = None
		primary_key = None
		request_method = None

		if self.initial_data.get("registration_id", None):
			if self.instance:
				request_method = "update"
				primary_key = self.instance.id
			else:
				request_method = "create"
		else:
			if self.context["request"].method in ["PUT", "PATCH"]:
				request_method = "update"
				primary_key = attrs["id"]
			elif self.context["request"].method == "POST":
				request_method = "create"

		Device = self.Meta.model
		if request_method == "update":
			devices = Device.objects.filter(registration_id=attrs["registration_id"]) \
				.exclude(id=primary_key).delete()
		elif request_method == "create":
			devices = Device.objects.filter(registration_id=attrs["registration_id"]).delete()

		return attrs


class APNSDeviceSerializer(OverwriteRegistrationSerializerMixin, ModelSerializer):
	class Meta(DeviceSerializerMixin.Meta):
		model = APNSDevice

	def validate_registration_id(self, value):
		# iOS device tokens are 256-bit hexadecimal (64 characters). In 2016 Apple is increasing
		# iOS device tokens to 100 bytes hexadecimal (200 characters).

		if hex_re.match(value) is None or len(value) not in (64, 200):
			raise ValidationError("Registration ID (device token) is invalid")

		return value


class UniqueRegistrationSerializerMixin(Serializer):
	def validate(self, attrs):
		devices = None
		primary_key = None
		request_method = None

		if self.initial_data.get("registration_id", None):
			if self.instance:
				request_method = "update"
				primary_key = self.instance.id
			else:
				request_method = "create"
		else:
			if self.context["request"].method in ["PUT", "PATCH"]:
				request_method = "update"
				primary_key = attrs["id"]
			elif self.context["request"].method == "POST":
				request_method = "create"

		Device = self.Meta.model
		if request_method == "update":
			devices = Device.objects.filter(registration_id=attrs["registration_id"]) \
				.exclude(id=primary_key)
		elif request_method == "create":
			devices = Device.objects.filter(registration_id=attrs["registration_id"])

		if devices:
			raise ValidationError({'registration_id': 'This field must be unique.'})
		return attrs


class GCMDeviceSerializer(OverwriteRegistrationSerializerMixin, ModelSerializer):
	device_id = HexIntegerField(
		help_text="ANDROID_ID / TelephonyManager.getDeviceId() (e.g: 0x01)",
		style={"input_type": "text"},
		required=False,
		allow_null=True
	)

	class Meta(DeviceSerializerMixin.Meta):
		model = GCMDevice

		extra_kwargs = {"id": {"read_only": False, "required": False}}

	def validate_device_id(self, value):
		# device ids are 64 bit unsigned values
		if value > UNSIGNED_64BIT_INT_MAX_VALUE:
			raise ValidationError("Device ID is out of range")
		return value


class WNSDeviceSerializer(OverwriteRegistrationSerializerMixin, ModelSerializer):
	class Meta(DeviceSerializerMixin.Meta):
		model = WNSDevice


# Permissions
class IsOwner(permissions.BasePermission):
	def has_object_permission(self, request, view, obj):
		# must be the owner to view the object
		return obj.user == request.user


# Mixins
class DeviceViewSetMixin(object):
	lookup_field = "registration_id"

	def perform_create(self, serializer):
		if self.request.user.is_authenticated():
			serializer.save(user=self.request.user)
		return super(DeviceViewSetMixin, self).perform_create(serializer)

	def perform_update(self, serializer):
		if self.request.user.is_authenticated():
			serializer.save(user=self.request.user)
		return super(DeviceViewSetMixin, self).perform_update(serializer)


class AuthorizedMixin(object):
	permission_classes = (permissions.IsAuthenticated, IsOwner)

	def get_queryset(self):
		# filter all devices to only those belonging to the current user
		return self.queryset.filter(user=self.request.user)


# ViewSets
class APNSDeviceViewSet(DeviceViewSetMixin, ModelViewSet):
	queryset = APNSDevice.objects.all()
	serializer_class = APNSDeviceSerializer


class APNSDeviceAuthorizedViewSet(AuthorizedMixin, APNSDeviceViewSet):
	pass


class GCMDeviceViewSet(DeviceViewSetMixin, ModelViewSet):
	queryset = GCMDevice.objects.all()
	serializer_class = GCMDeviceSerializer


class GCMDeviceAuthorizedViewSet(AuthorizedMixin, GCMDeviceViewSet):
	pass


class WNSDeviceViewSet(DeviceViewSetMixin, ModelViewSet):
	queryset = WNSDevice.objects.all()
	serializer_class = WNSDeviceSerializer


class WNSDeviceAuthorizedViewSet(AuthorizedMixin, WNSDeviceViewSet):
	pass
